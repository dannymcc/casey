from flask import Flask, render_template, request, redirect, url_for, jsonify, g, session, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from functools import wraps
import sqlite3
import random
import os
import secrets
import hashlib

app = Flask(__name__)

# Require a strong SECRET_KEY in production
_secret = os.environ.get('SECRET_KEY', '')
_weak_keys = {'', 'dev-secret-key-change-in-production', 'change-this-in-production'}
if _secret in _weak_keys and not os.environ.get('FLASK_DEBUG', 'False') == 'True':
    raise RuntimeError('SECRET_KEY must be set to a strong random value in production. '
                       'Generate one with: python -c "import secrets; print(secrets.token_hex(32))"')
app.config['SECRET_KEY'] = _secret or 'dev-secret-key-for-local-only'
app.config['VERSION'] = os.environ.get('VERSION', 'dev')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_DEBUG', 'False') != 'True'

# CSRF protection
csrf = CSRFProtect(app)

# Rate limiting
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"],
                  storage_uri="memory://")

# Ensure data directory exists
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE = os.path.join(DATA_DIR, 'casey.db')
API_KEY_FILE = os.path.join(DATA_DIR, '.api_key')


# --- Database ---

def get_db():
    """Get database connection, stored on Flask g for request lifecycle."""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database with schema."""
    db = sqlite3.connect(DATABASE)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS journal_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(date, user_id)
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT 0,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS blips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_surfaced TIMESTAMP,
            surface_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS daily_blips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            journal_date TEXT NOT NULL,
            blip_id INTEGER NOT NULL,
            user_id INTEGER,
            FOREIGN KEY (blip_id) REFERENCES blips (id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(journal_date, blip_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_used_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    ''')

    # Migrations for existing databases
    cursor = db.execute("PRAGMA table_info(blips)")
    columns = [row[1] for row in cursor.fetchall()]

    if 'updated_at' not in columns:
        db.execute('ALTER TABLE blips ADD COLUMN updated_at TIMESTAMP')
        db.execute('UPDATE blips SET updated_at = created_at')

    if 'user_id' not in columns:
        db.execute('ALTER TABLE blips ADD COLUMN user_id INTEGER')

    cursor = db.execute("PRAGMA table_info(tasks)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'user_id' not in columns:
        db.execute('ALTER TABLE tasks ADD COLUMN user_id INTEGER')

    cursor = db.execute("PRAGMA table_info(journal_entries)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'user_id' not in columns:
        db.execute('ALTER TABLE journal_entries ADD COLUMN user_id INTEGER')
        # Recreate unique constraint -- SQLite doesn't support dropping constraints,
        # but new rows will use the (date, user_id) pair. Old rows with NULL user_id
        # still work because UNIQUE treats each NULL as distinct.

    cursor = db.execute("PRAGMA table_info(daily_blips)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'user_id' not in columns:
        db.execute('ALTER TABLE daily_blips ADD COLUMN user_id INTEGER')

    # Check if old unique constraint needs updating -- for new installs this is
    # handled by CREATE TABLE. For existing DBs, the old UNIQUE(journal_date, blip_id)
    # still works since user_id will be NULL for legacy data.

    # Migrate old single API key into api_tokens table
    token_count = db.execute('SELECT COUNT(*) FROM api_tokens').fetchone()[0]
    if token_count == 0:
        old_key = None
        env_key = os.environ.get('API_KEY')
        if env_key:
            old_key = env_key
        else:
            try:
                with open(API_KEY_FILE, 'r') as f:
                    key = f.read().strip()
                    if key:
                        old_key = key
            except FileNotFoundError:
                pass
        if old_key:
            db.execute('INSERT INTO api_tokens (name, token) VALUES (?, ?)',
                       ('Default', hashlib.sha256(old_key.encode()).hexdigest()))
        else:
            token = secrets.token_urlsafe(32)
            db.execute('INSERT INTO api_tokens (name, token) VALUES (?, ?)',
                       ('Default', hashlib.sha256(token.encode()).hexdigest()))

    # Auth is always enabled for SaaS — ensure setting is 'true'
    existing_auth = db.execute("SELECT value FROM app_settings WHERE key = 'auth_enabled'").fetchone()
    if not existing_auth:
        db.execute("INSERT INTO app_settings (key, value) VALUES ('auth_enabled', 'true')")
    elif existing_auth[0] != 'true':
        db.execute("UPDATE app_settings SET value = 'true' WHERE key = 'auth_enabled'")

    db.commit()
    db.close()


# --- Auth helpers ---

def is_auth_enabled():
    """Authentication is always enabled for SaaS."""
    return True


def get_current_user_id():
    """Get current user ID, or None if auth is disabled."""
    if not is_auth_enabled():
        return None
    return session.get('user_id')


def login_required(f):
    """Decorator: redirect to login if auth enabled and user not logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if is_auth_enabled() and 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def user_filter(table_alias=''):
    """Return (sql_fragment, params) for filtering by current user.

    When auth is disabled, returns a no-op filter.
    When auth is enabled, filters to current user's data.
    """
    prefix = f'{table_alias}.' if table_alias else ''
    user_id = get_current_user_id()
    if user_id is not None:
        return f'{prefix}user_id = ?', (user_id,)
    return f'{prefix}user_id IS NULL', ()


# --- Template filters ---

@app.template_filter('uk_date')
def uk_date_filter(date_string):
    """Format date to British DD/MM/YYYY format."""
    if not date_string:
        return ''
    try:
        dt = datetime.fromisoformat(date_string.split('T')[0])
        return dt.strftime('%d/%m/%Y')
    except (ValueError, AttributeError):
        return date_string


@app.template_filter('uk_date_long')
def uk_date_long_filter(date_string):
    """Format date to British long format (e.g., Monday, 9 February 2026)."""
    if not date_string:
        return ''
    try:
        dt = datetime.fromisoformat(date_string.split('T')[0])
        return dt.strftime('%A, %-d %B %Y')
    except (ValueError, AttributeError):
        return date_string


@app.context_processor
def inject_auth():
    """Make auth state available to all templates."""
    return {
        'auth_enabled': is_auth_enabled(),
        'current_user': session.get('username') if is_auth_enabled() else None,
    }


@app.after_request
def set_security_headers(response):
    """Set security headers on all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if request.is_secure:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


# --- Auth routes ---

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if not is_auth_enabled():
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')

        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('index'))

        flash('Invalid username or password.', 'error')
        return render_template('login.html')

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour", methods=["POST"])
def register():
    if not is_auth_enabled():
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('register.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')

        db = get_db()
        existing = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            flash('Username already taken.', 'error')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        cursor = db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                            (username, password_hash))
        db.commit()

        session['user_id'] = cursor.lastrowid
        session['username'] = username
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login') if is_auth_enabled() else url_for('index'))


# --- Page routes ---

@app.route('/')
@login_required
def index():
    """Main dashboard."""
    db = get_db()
    today = date.today().isoformat()
    uf, uf_params = user_filter()

    # Get or create today's journal entry
    journal = db.execute(
        f'SELECT * FROM journal_entries WHERE date = ? AND {uf}',
        (today, *uf_params)
    ).fetchone()

    # Get active tasks
    tasks = db.execute(
        f'SELECT * FROM tasks WHERE completed = 0 AND {uf} ORDER BY created_at DESC',
        uf_params
    ).fetchall()

    # Get today's blips (or select 3 random ones if none selected yet)
    daily_uf, daily_uf_params = user_filter('db')
    daily_blips = db.execute(f'''
        SELECT b.* FROM blips b
        JOIN daily_blips db ON b.id = db.blip_id
        WHERE db.journal_date = ? AND {daily_uf}
        ORDER BY b.last_surfaced ASC
    ''', (today, *daily_uf_params)).fetchall()

    if not daily_blips:
        blip_uf, blip_uf_params = user_filter()
        daily_blips = db.execute(f'''
            SELECT * FROM blips WHERE {blip_uf}
            ORDER BY RANDOM()
            LIMIT 3
        ''', blip_uf_params).fetchall()

        user_id = get_current_user_id()
        for blip in daily_blips:
            db.execute(
                'INSERT OR IGNORE INTO daily_blips (journal_date, blip_id, user_id) VALUES (?, ?, ?)',
                (today, blip['id'], user_id)
            )
            db.execute(
                'UPDATE blips SET last_surfaced = ?, surface_count = surface_count + 1 WHERE id = ?',
                (datetime.now().isoformat(), blip['id'])
            )
        db.commit()

    return render_template('index.html',
                           journal=journal,
                           tasks=tasks,
                           blips=daily_blips,
                           today=today)


@app.route('/journal/save', methods=['POST'])
@login_required
def save_journal():
    """Save journal entry."""
    today = date.today().isoformat()
    content = request.form.get('content', '')
    user_id = get_current_user_id()

    db = get_db()
    uf, uf_params = user_filter()

    # Check if entry exists for this user+date
    existing = db.execute(
        f'SELECT id FROM journal_entries WHERE date = ? AND {uf}',
        (today, *uf_params)
    ).fetchone()

    if existing:
        db.execute(
            'UPDATE journal_entries SET content = ?, updated_at = ? WHERE id = ?',
            (content, datetime.now().isoformat(), existing['id'])
        )
    else:
        db.execute(
            'INSERT INTO journal_entries (date, content, user_id, updated_at) VALUES (?, ?, ?, ?)',
            (today, content, user_id, datetime.now().isoformat())
        )
    db.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'saved': True})

    return redirect(url_for('index'))


@app.route('/tasks/add', methods=['POST'])
@login_required
def add_task():
    """Add new task."""
    title = request.form.get('title', '').strip()
    if title:
        db = get_db()
        user_id = get_current_user_id()
        db.execute('INSERT INTO tasks (title, user_id) VALUES (?, ?)', (title, user_id))
        db.commit()

    return redirect(url_for('index'))


@app.route('/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def toggle_task(task_id):
    """Toggle task completion."""
    db = get_db()
    uf, uf_params = user_filter()
    task = db.execute(
        f'SELECT * FROM tasks WHERE id = ? AND {uf}',
        (task_id, *uf_params)
    ).fetchone()

    if task:
        new_state = 0 if task['completed'] else 1
        completed_at = datetime.now().isoformat() if new_state else None
        db.execute('UPDATE tasks SET completed = ?, completed_at = ? WHERE id = ?',
                   (new_state, completed_at, task_id))
        db.commit()

    return redirect(url_for('index'))


@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    """Delete task."""
    db = get_db()
    uf, uf_params = user_filter()
    db.execute(f'DELETE FROM tasks WHERE id = ? AND {uf}', (task_id, *uf_params))
    db.commit()

    return redirect(url_for('index'))


@app.route('/blips')
@login_required
def blips_list():
    """View all blips."""
    db = get_db()
    uf, uf_params = user_filter()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    blips = db.execute(
        f'SELECT * FROM blips WHERE {uf} ORDER BY created_at DESC LIMIT ? OFFSET ?',
        (*uf_params, per_page + 1, offset)
    ).fetchall()
    has_more = len(blips) > per_page
    blips = blips[:per_page]

    return render_template('blips.html', blips=blips, page=page, has_more=has_more)


@app.route('/blips/add', methods=['POST'])
@login_required
def add_blip():
    """Add new blip."""
    content = request.form.get('content', '').strip()
    if content:
        db = get_db()
        user_id = get_current_user_id()
        db.execute('INSERT INTO blips (content, user_id) VALUES (?, ?)', (content, user_id))
        db.commit()

    return redirect(url_for('blips_list'))


@app.route('/blips/<int:blip_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_blip(blip_id):
    """Edit existing blip."""
    db = get_db()
    uf, uf_params = user_filter()

    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if content:
            db.execute(
                f'UPDATE blips SET content = ?, updated_at = ? WHERE id = ? AND {uf}',
                (content, datetime.now().isoformat(), blip_id, *uf_params)
            )
            db.commit()
        return redirect(url_for('blips_list'))

    blip = db.execute(
        f'SELECT * FROM blips WHERE id = ? AND {uf}',
        (blip_id, *uf_params)
    ).fetchone()

    if not blip:
        return redirect(url_for('blips_list'))

    return render_template('edit_blip.html', blip=blip)


@app.route('/blips/<int:blip_id>/delete', methods=['POST'])
@login_required
def delete_blip(blip_id):
    """Delete blip."""
    db = get_db()
    uf, uf_params = user_filter()
    db.execute(f'DELETE FROM daily_blips WHERE blip_id = ? AND {uf}', (blip_id, *uf_params))
    db.execute(f'DELETE FROM blips WHERE id = ? AND {uf}', (blip_id, *uf_params))
    db.commit()

    return redirect(url_for('blips_list'))


@app.route('/history')
@login_required
def history():
    """View journal history."""
    db = get_db()
    uf, uf_params = user_filter()
    page = request.args.get('page', 1, type=int)
    per_page = 30
    offset = (page - 1) * per_page
    entries = db.execute(
        f'SELECT * FROM journal_entries WHERE {uf} ORDER BY date DESC LIMIT ? OFFSET ?',
        (*uf_params, per_page + 1, offset)
    ).fetchall()
    has_more = len(entries) > per_page
    entries = entries[:per_page]

    return render_template('history.html', entries=entries, page=page, has_more=has_more)


@app.route('/completed-tasks')
@login_required
def completed_tasks():
    """View completed tasks."""
    db = get_db()
    uf, uf_params = user_filter()
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    tasks = db.execute(
        f'SELECT * FROM tasks WHERE completed = 1 AND {uf} ORDER BY completed_at DESC LIMIT ? OFFSET ?',
        (*uf_params, per_page + 1, offset)
    ).fetchall()
    has_more = len(tasks) > per_page
    tasks = tasks[:per_page]

    return render_template('completed_tasks.html', tasks=tasks, page=page, has_more=has_more)


@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')


@app.route('/api')
def api_docs():
    """API documentation."""
    return render_template('api.html')


@app.route('/settings')
@login_required
def settings():
    """Settings page."""
    return render_template('settings.html', version=app.config['VERSION'])


@app.route('/settings/api')
@login_required
def settings_api():
    """API settings page."""
    db = get_db()
    user_id = get_current_user_id()
    if user_id is not None:
        tokens = db.execute('SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC', (user_id,)).fetchall()
    else:
        tokens = db.execute('SELECT * FROM api_tokens WHERE user_id IS NULL ORDER BY created_at DESC').fetchall()
    new_token = session.pop('new_token', None)
    return render_template('settings_api.html', tokens=tokens, new_token=new_token)


@app.route('/settings/api/tokens/create', methods=['POST'])
@login_required
def create_api_token():
    """Create a new API token."""
    name = request.form.get('name', '').strip()
    if not name:
        name = 'Untitled'
    token = secrets.token_urlsafe(32)
    token_hashed = hash_token(token)
    user_id = get_current_user_id()
    db = get_db()
    db.execute('INSERT INTO api_tokens (user_id, name, token) VALUES (?, ?, ?)',
               (user_id, name, token_hashed))
    db.commit()
    session['new_token'] = token  # Show plaintext once
    flash('Token created successfully.', 'success')
    return redirect(url_for('settings_api'))


@app.route('/settings/api/tokens/<int:token_id>/revoke', methods=['POST'])
@login_required
def revoke_api_token(token_id):
    """Revoke an API token."""
    db = get_db()
    uf, uf_params = user_filter()
    db.execute(f'DELETE FROM api_tokens WHERE id = ? AND {uf}', (token_id, *uf_params))
    db.commit()
    flash('Token revoked.', 'success')
    return redirect(url_for('settings_api'))


## Auth toggle removed — auth is always on for SaaS


@app.route('/settings/account')
@login_required
def settings_account():
    """Account settings page."""
    if not is_auth_enabled():
        return redirect(url_for('settings'))
    return render_template('settings_account.html')


@app.route('/settings/account/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password."""
    if not is_auth_enabled():
        return redirect(url_for('settings'))

    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if not current_password or not new_password:
        flash('Please fill in all fields.', 'error')
        return redirect(url_for('settings_account'))

    if len(new_password) < 6:
        flash('New password must be at least 6 characters.', 'error')
        return redirect(url_for('settings_account'))

    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('settings_account'))

    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or not check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('settings_account'))

    db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
               (generate_password_hash(new_password), session['user_id']))
    db.commit()
    flash('Password updated successfully.', 'success')
    return redirect(url_for('settings_account'))


# --- API Authentication ---

def hash_token(token):
    """Hash an API token using SHA-256 for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        db = get_db()
        token_hash = hash_token(api_key)
        # Check hashed tokens first, fall back to plaintext for migration
        token_row = db.execute('SELECT * FROM api_tokens WHERE token = ?', (token_hash,)).fetchone()
        if not token_row:
            # Migration: check for plaintext token and hash it
            token_row = db.execute('SELECT * FROM api_tokens WHERE token = ?', (api_key,)).fetchone()
            if token_row:
                db.execute('UPDATE api_tokens SET token = ? WHERE id = ?',
                           (token_hash, token_row['id']))
        if not token_row:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        db.execute('UPDATE api_tokens SET last_used_at = ? WHERE id = ?',
                   (datetime.now().isoformat(), token_row['id']))
        db.commit()
        g.api_token = token_row
        g.api_user_id = token_row['user_id']
        return f(*args, **kwargs)
    return decorated_function


def api_user_filter(table_alias=''):
    """Return (sql_fragment, params) for filtering API queries by token owner."""
    prefix = f'{table_alias}.' if table_alias else ''
    user_id = g.get('api_user_id')
    if user_id is not None:
        return f'{prefix}user_id = ?', (user_id,)
    return f'{prefix}user_id IS NULL', ()


# --- API Endpoints ---

@app.route('/api/journal', methods=['GET'])
@csrf.exempt
@require_api_key
def api_get_journal():
    """Get journal entries."""
    limit = request.args.get('limit', 30, type=int)
    db = get_db()
    uf, uf_params = api_user_filter()
    entries = db.execute(f'SELECT * FROM journal_entries WHERE {uf} ORDER BY date DESC LIMIT ?',
                         (*uf_params, limit)).fetchall()
    return jsonify({'entries': [dict(entry) for entry in entries]})


@app.route('/api/journal/<date_str>', methods=['GET', 'POST'])
@csrf.exempt
@require_api_key
def api_journal_entry(date_str):
    """Get or create journal entry for a specific date."""
    db = get_db()

    uf, uf_params = api_user_filter()

    if request.method == 'POST':
        content = request.json.get('content', '')
        existing = db.execute(f'SELECT id FROM journal_entries WHERE date = ? AND {uf}',
                              (date_str, *uf_params)).fetchone()
        if existing:
            db.execute('UPDATE journal_entries SET content = ?, updated_at = ? WHERE id = ?',
                       (content, datetime.now().isoformat(), existing['id']))
        else:
            db.execute('INSERT INTO journal_entries (date, content, user_id, updated_at) VALUES (?, ?, ?, ?)',
                       (date_str, content, g.api_user_id, datetime.now().isoformat()))
        db.commit()
        entry = db.execute(f'SELECT * FROM journal_entries WHERE date = ? AND {uf}',
                           (date_str, *uf_params)).fetchone()
        return jsonify({'entry': dict(entry)})

    entry = db.execute(f'SELECT * FROM journal_entries WHERE date = ? AND {uf}',
                       (date_str, *uf_params)).fetchone()
    if entry:
        return jsonify({'entry': dict(entry)})
    return jsonify({'error': 'Entry not found'}), 404


@app.route('/api/tasks', methods=['GET', 'POST'])
@csrf.exempt
@require_api_key
def api_tasks():
    """Get all tasks or create a new task."""
    db = get_db()

    uf, uf_params = api_user_filter()

    if request.method == 'POST':
        title = request.json.get('title', '').strip()
        if not title:
            return jsonify({'error': 'Title is required'}), 400
        cursor = db.execute('INSERT INTO tasks (title, user_id) VALUES (?, ?)', (title, g.api_user_id))
        task_id = cursor.lastrowid
        db.commit()
        task = db.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
        return jsonify({'task': dict(task)}), 201

    completed = request.args.get('completed', type=int)
    if completed is not None:
        tasks = db.execute(f'SELECT * FROM tasks WHERE completed = ? AND {uf} ORDER BY created_at DESC',
                           (completed, *uf_params)).fetchall()
    else:
        tasks = db.execute(f'SELECT * FROM tasks WHERE {uf} ORDER BY created_at DESC',
                           uf_params).fetchall()
    return jsonify({'tasks': [dict(task) for task in tasks]})


@app.route('/api/tasks/<int:task_id>', methods=['GET', 'PUT', 'DELETE'])
@csrf.exempt
@require_api_key
def api_task(task_id):
    """Get, update, or delete a specific task."""
    db = get_db()

    uf, uf_params = api_user_filter()

    if request.method == 'DELETE':
        db.execute(f'DELETE FROM tasks WHERE id = ? AND {uf}', (task_id, *uf_params))
        db.commit()
        return jsonify({'success': True})

    if request.method == 'PUT':
        data = request.json
        if 'completed' in data:
            completed_at = datetime.now().isoformat() if data['completed'] else None
            db.execute(f'UPDATE tasks SET completed = ?, completed_at = ? WHERE id = ? AND {uf}',
                       (data['completed'], completed_at, task_id, *uf_params))
        if 'title' in data:
            db.execute(f'UPDATE tasks SET title = ? WHERE id = ? AND {uf}',
                       (data['title'], task_id, *uf_params))
        db.commit()

    task = db.execute(f'SELECT * FROM tasks WHERE id = ? AND {uf}',
                      (task_id, *uf_params)).fetchone()
    if task:
        return jsonify({'task': dict(task)})
    return jsonify({'error': 'Task not found'}), 404


@app.route('/api/blips', methods=['GET', 'POST'])
@csrf.exempt
@require_api_key
def api_blips():
    """Get all blips or create a new blip."""
    db = get_db()

    uf, uf_params = api_user_filter()

    if request.method == 'POST':
        content = request.json.get('content', '').strip()
        if not content:
            return jsonify({'error': 'Content is required'}), 400
        cursor = db.execute('INSERT INTO blips (content, user_id) VALUES (?, ?)', (content, g.api_user_id))
        blip_id = cursor.lastrowid
        db.commit()
        blip = db.execute('SELECT * FROM blips WHERE id = ?', (blip_id,)).fetchone()
        return jsonify({'blip': dict(blip)}), 201

    blips = db.execute(f'SELECT * FROM blips WHERE {uf} ORDER BY created_at DESC',
                       uf_params).fetchall()
    return jsonify({'blips': [dict(blip) for blip in blips]})


@app.route('/api/blips/<int:blip_id>', methods=['GET', 'DELETE'])
@csrf.exempt
@require_api_key
def api_blip(blip_id):
    """Get or delete a specific blip."""
    db = get_db()

    uf, uf_params = api_user_filter()

    if request.method == 'DELETE':
        db.execute(f'DELETE FROM daily_blips WHERE blip_id = ? AND {uf}', (blip_id, *uf_params))
        db.execute(f'DELETE FROM blips WHERE id = ? AND {uf}', (blip_id, *uf_params))
        db.commit()
        return jsonify({'success': True})

    blip = db.execute(f'SELECT * FROM blips WHERE id = ? AND {uf}',
                      (blip_id, *uf_params)).fetchone()
    if blip:
        return jsonify({'blip': dict(blip)})
    return jsonify({'error': 'Blip not found'}), 404


# Initialize database on startup (works with both Gunicorn and direct run)
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5090, debug=os.environ.get('FLASK_DEBUG', 'False') == 'True')
