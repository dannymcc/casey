from flask import Flask, render_template, request, redirect, url_for, jsonify
from datetime import datetime, date
import sqlite3
import random
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

DATABASE = 'casey.db'

def get_db():
    """Get database connection"""
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    """Initialize database with schema"""
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS journal_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT UNIQUE NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        );
        
        CREATE TABLE IF NOT EXISTS blips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_surfaced TIMESTAMP,
            surface_count INTEGER DEFAULT 0
        );
        
        CREATE TABLE IF NOT EXISTS daily_blips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            journal_date TEXT NOT NULL,
            blip_id INTEGER NOT NULL,
            FOREIGN KEY (blip_id) REFERENCES blips (id),
            UNIQUE(journal_date, blip_id)
        );
    ''')
    db.commit()
    db.close()

@app.route('/')
def index():
    """Main dashboard"""
    db = get_db()
    today = date.today().isoformat()
    
    # Get or create today's journal entry
    journal = db.execute('SELECT * FROM journal_entries WHERE date = ?', (today,)).fetchone()
    
    # Get active tasks
    tasks = db.execute('SELECT * FROM tasks WHERE completed = 0 ORDER BY created_at DESC').fetchall()
    
    # Get today's blips (or select 3 random ones if none selected yet)
    daily_blips = db.execute('''
        SELECT b.* FROM blips b
        JOIN daily_blips db ON b.id = db.blip_id
        WHERE db.journal_date = ?
        ORDER BY b.last_surfaced ASC
    ''', (today,)).fetchall()
    
    if not daily_blips:
        # Select 3 random blips that haven't been surfaced recently
        daily_blips = db.execute('''
            SELECT * FROM blips
            ORDER BY RANDOM()
            LIMIT 3
        ''').fetchall()
        
        # Record these as today's blips
        for blip in daily_blips:
            db.execute('INSERT OR IGNORE INTO daily_blips (journal_date, blip_id) VALUES (?, ?)', 
                      (today, blip['id']))
            db.execute('UPDATE blips SET last_surfaced = ?, surface_count = surface_count + 1 WHERE id = ?',
                      (datetime.now().isoformat(), blip['id']))
        db.commit()
    
    db.close()
    
    return render_template('index.html', 
                         journal=journal,
                         tasks=tasks,
                         blips=daily_blips,
                         today=today)

@app.route('/journal/save', methods=['POST'])
def save_journal():
    """Save journal entry"""
    today = date.today().isoformat()
    content = request.form.get('content', '')
    
    db = get_db()
    db.execute('''
        INSERT INTO journal_entries (date, content, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(date) DO UPDATE SET
            content = excluded.content,
            updated_at = excluded.updated_at
    ''', (today, content, datetime.now().isoformat()))
    db.commit()
    db.close()
    
    return redirect(url_for('index'))

@app.route('/tasks/add', methods=['POST'])
def add_task():
    """Add new task"""
    title = request.form.get('title', '').strip()
    if title:
        db = get_db()
        db.execute('INSERT INTO tasks (title) VALUES (?)', (title,))
        db.commit()
        db.close()
    
    return redirect(url_for('index'))

@app.route('/tasks/<int:task_id>/toggle', methods=['POST'])
def toggle_task(task_id):
    """Toggle task completion"""
    db = get_db()
    task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    
    if task:
        new_state = 0 if task['completed'] else 1
        completed_at = datetime.now().isoformat() if new_state else None
        db.execute('UPDATE tasks SET completed = ?, completed_at = ? WHERE id = ?',
                  (new_state, completed_at, task_id))
        db.commit()
    
    db.close()
    return redirect(url_for('index'))

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
def delete_task(task_id):
    """Delete task"""
    db = get_db()
    db.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    db.commit()
    db.close()
    
    return redirect(url_for('index'))

@app.route('/blips')
def blips_list():
    """View all blips"""
    db = get_db()
    blips = db.execute('SELECT * FROM blips ORDER BY created_at DESC').fetchall()
    db.close()
    
    return render_template('blips.html', blips=blips)

@app.route('/blips/add', methods=['POST'])
def add_blip():
    """Add new blip"""
    content = request.form.get('content', '').strip()
    if content:
        db = get_db()
        db.execute('INSERT INTO blips (content) VALUES (?)', (content,))
        db.commit()
        db.close()
    
    return redirect(url_for('blips_list'))

@app.route('/blips/<int:blip_id>/delete', methods=['POST'])
def delete_blip(blip_id):
    """Delete blip"""
    db = get_db()
    db.execute('DELETE FROM daily_blips WHERE blip_id = ?', (blip_id,))
    db.execute('DELETE FROM blips WHERE id = ?', (blip_id,))
    db.commit()
    db.close()
    
    return redirect(url_for('blips_list'))

@app.route('/history')
def history():
    """View journal history"""
    db = get_db()
    entries = db.execute('SELECT * FROM journal_entries ORDER BY date DESC LIMIT 30').fetchall()
    db.close()
    
    return render_template('history.html', entries=entries)

@app.route('/completed-tasks')
def completed_tasks():
    """View completed tasks"""
    db = get_db()
    tasks = db.execute('SELECT * FROM tasks WHERE completed = 1 ORDER BY completed_at DESC LIMIT 50').fetchall()
    db.close()
    
    return render_template('completed_tasks.html', tasks=tasks)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5090, debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')
