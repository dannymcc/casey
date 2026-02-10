from flask import Flask, render_template, request, redirect, url_for, jsonify, g, session, flash, Response
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
from markupsafe import Markup
import sqlite3
import random
import math
import json
import csv
import io
import os
import secrets
import hashlib
import markdown
import pyotp

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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

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

        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(name, user_id)
        );

        CREATE TABLE IF NOT EXISTS journal_tags (
            journal_entry_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            PRIMARY KEY (journal_entry_id, tag_id),
            FOREIGN KEY (journal_entry_id) REFERENCES journal_entries (id),
            FOREIGN KEY (tag_id) REFERENCES tags (id)
        );

        CREATE TABLE IF NOT EXISTS user_preferences (
            user_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY (user_id, key),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            detail TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS subtasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT 0,
            sort_order INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES tasks (id) ON DELETE CASCADE
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
    if 'pinned' not in columns:
        db.execute('ALTER TABLE blips ADD COLUMN pinned INTEGER DEFAULT 0')
    if 'archived' not in columns:
        db.execute('ALTER TABLE blips ADD COLUMN archived INTEGER DEFAULT 0')

    cursor = db.execute("PRAGMA table_info(tasks)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'user_id' not in columns:
        db.execute('ALTER TABLE tasks ADD COLUMN user_id INTEGER')
    if 'due_date' not in columns:
        db.execute('ALTER TABLE tasks ADD COLUMN due_date TEXT')
    if 'priority' not in columns:
        db.execute('ALTER TABLE tasks ADD COLUMN priority INTEGER DEFAULT 0')
    if 'recurrence' not in columns:
        db.execute("ALTER TABLE tasks ADD COLUMN recurrence TEXT DEFAULT 'none'")
    if 'notes' not in columns:
        db.execute('ALTER TABLE tasks ADD COLUMN notes TEXT')

    cursor = db.execute("PRAGMA table_info(journal_entries)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'user_id' not in columns:
        db.execute('ALTER TABLE journal_entries ADD COLUMN user_id INTEGER')
        # Recreate unique constraint -- SQLite doesn't support dropping constraints,
        # but new rows will use the (date, user_id) pair. Old rows with NULL user_id
        # still work because UNIQUE treats each NULL as distinct.
    if 'mood' not in columns:
        db.execute('ALTER TABLE journal_entries ADD COLUMN mood INTEGER')

    cursor = db.execute("PRAGMA table_info(daily_blips)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'user_id' not in columns:
        db.execute('ALTER TABLE daily_blips ADD COLUMN user_id INTEGER')

    # Check if old unique constraint needs updating -- for new installs this is
    # handled by CREATE TABLE. For existing DBs, the old UNIQUE(journal_date, blip_id)
    # still works since user_id will be NULL for legacy data.

    # Admin role migration
    cursor = db.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    if 'is_admin' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
        # Make first user admin by default
        first_user = db.execute('SELECT id FROM users ORDER BY id LIMIT 1').fetchone()
        if first_user:
            db.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (first_user[0],))
    if 'totp_secret' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')

    # Full-text search virtual tables
    db.executescript('''
        CREATE VIRTUAL TABLE IF NOT EXISTS journal_fts USING fts5(
            content, date, content='journal_entries', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS blips_fts USING fts5(
            content, content='blips', content_rowid='id'
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS tasks_fts USING fts5(
            title, content='tasks', content_rowid='id'
        );
    ''')

    # Rebuild FTS indexes if empty
    fts_count = db.execute('SELECT COUNT(*) FROM journal_fts').fetchone()[0]
    if fts_count == 0:
        db.execute("INSERT INTO journal_fts(journal_fts) VALUES('rebuild')")
        db.execute("INSERT INTO blips_fts(blips_fts) VALUES('rebuild')")
        db.execute("INSERT INTO tasks_fts(tasks_fts) VALUES('rebuild')")

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


def admin_required(f):
    """Decorator: require admin access."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if not user or not user['is_admin']:
            return redirect(url_for('index'))
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


def audit_log(action, detail=None):
    """Record an audit event for the current user."""
    try:
        db = get_db()
        user_id = get_current_user_id()
        ip = request.remote_addr if request else None
        db.execute(
            'INSERT INTO audit_log (user_id, action, detail, ip_address) VALUES (?, ?, ?, ?)',
            (user_id, action, detail, ip)
        )
        db.commit()
    except Exception:
        pass  # Never let audit logging break the app


# --- User preferences ---

def get_preference(user_id, key, default=None):
    """Get a user preference value."""
    if user_id is None:
        return default
    db = get_db()
    row = db.execute('SELECT value FROM user_preferences WHERE user_id = ? AND key = ?',
                     (user_id, key)).fetchone()
    return row['value'] if row else default


def set_preference(user_id, key, value):
    """Set a user preference value."""
    if user_id is None:
        return
    db = get_db()
    db.execute('INSERT OR REPLACE INTO user_preferences (user_id, key, value) VALUES (?, ?, ?)',
               (user_id, key, str(value)))
    db.commit()


def save_journal_tags(db, journal_entry_id, user_id, tags_str):
    """Parse comma-separated tags and save them for a journal entry."""
    # Clear existing tags for this entry
    db.execute('DELETE FROM journal_tags WHERE journal_entry_id = ?', (journal_entry_id,))
    if not tags_str or not tags_str.strip():
        return
    tag_names = [t.strip().lower() for t in tags_str.split(',') if t.strip()]
    for name in tag_names:
        # Get or create tag
        existing = db.execute('SELECT id FROM tags WHERE name = ? AND user_id = ?',
                              (name, user_id)).fetchone()
        if existing:
            tag_id = existing['id']
        else:
            cursor = db.execute('INSERT INTO tags (name, user_id) VALUES (?, ?)',
                                (name, user_id))
            tag_id = cursor.lastrowid
        db.execute('INSERT OR IGNORE INTO journal_tags (journal_entry_id, tag_id) VALUES (?, ?)',
                   (journal_entry_id, tag_id))


def get_journal_tags(db, journal_entry_id):
    """Get tags for a journal entry."""
    return db.execute('''
        SELECT t.name FROM tags t
        JOIN journal_tags jt ON t.id = jt.tag_id
        WHERE jt.journal_entry_id = ?
        ORDER BY t.name
    ''', (journal_entry_id,)).fetchall()


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


@app.template_filter('markdown')
def markdown_filter(text):
    """Render markdown to HTML."""
    if not text:
        return ''
    html = markdown.markdown(text, extensions=['nl2br', 'smarty', 'fenced_code'])
    return Markup(html)


@app.template_filter('word_count')
def word_count_filter(text):
    """Count words in text."""
    if not text:
        return 0
    return len(text.split())


@app.context_processor
def inject_auth():
    """Make auth state available to all templates."""
    is_admin = False
    if is_auth_enabled() and session.get('user_id'):
        try:
            db = get_db()
            user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
            is_admin = bool(user and user['is_admin'])
        except Exception:
            pass
    return {
        'auth_enabled': is_auth_enabled(),
        'current_user': session.get('username') if is_auth_enabled() else None,
        'is_admin': is_admin,
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
            if user['totp_secret']:
                # 2FA enabled: store pending auth and redirect to TOTP page
                session['pending_2fa_user_id'] = user['id']
                session['pending_2fa_username'] = user['username']
                return redirect(url_for('verify_2fa'))
            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            audit_log('login', f'User {username} logged in')
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
        # First user gets admin privileges
        user_count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        is_admin = 1 if user_count == 0 else 0
        cursor = db.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)',
                            (username, password_hash, is_admin))
        db.commit()

        session.permanent = True
        session['user_id'] = cursor.lastrowid
        session['username'] = username
        audit_log('register', f'New account created: {username}')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    """Verify TOTP code during login."""
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?',
                          (session['pending_2fa_user_id'],)).fetchone()
        if user and user['totp_secret']:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(code, valid_window=1):
                user_id = session.pop('pending_2fa_user_id')
                username = session.pop('pending_2fa_username')
                session.permanent = True
                session['user_id'] = user_id
                session['username'] = username
                audit_log('login', f'User {username} logged in (2FA)')
                return redirect(url_for('index'))
        flash('Invalid verification code.', 'error')

    return render_template('verify_2fa.html')


@app.route('/settings/2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    """Set up or disable two-factor authentication."""
    db = get_db()
    user = db.execute('SELECT totp_secret FROM users WHERE id = ?',
                      (session['user_id'],)).fetchone()
    has_2fa = bool(user and user['totp_secret'])

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable':
            secret = pyotp.random_base32()
            code = request.form.get('code', '').strip()
            totp = pyotp.TOTP(secret)
            stored_secret = request.form.get('secret', '')
            if stored_secret:
                # Verify the code matches the secret being set up
                totp = pyotp.TOTP(stored_secret)
                if totp.verify(code, valid_window=1):
                    db.execute('UPDATE users SET totp_secret = ? WHERE id = ?',
                               (stored_secret, session['user_id']))
                    db.commit()
                    audit_log('2fa_enable', '2FA enabled')
                    flash('Two-factor authentication enabled.', 'success')
                    return redirect(url_for('settings'))
                else:
                    flash('Invalid code. Please try again.', 'error')
                    return render_template('setup_2fa.html', secret=stored_secret,
                                           provisioning_uri=pyotp.TOTP(stored_secret).provisioning_uri(
                                               session.get('username', ''), issuer_name='Casey'),
                                           has_2fa=False, step='verify')
            # Generate new secret and show setup page
            uri = totp.provisioning_uri(session.get('username', ''), issuer_name='Casey')
            return render_template('setup_2fa.html', secret=secret,
                                   provisioning_uri=uri, has_2fa=False, step='verify')
        elif action == 'disable':
            password = request.form.get('password', '')
            user_full = db.execute('SELECT * FROM users WHERE id = ?',
                                   (session['user_id'],)).fetchone()
            if user_full and check_password_hash(user_full['password_hash'], password):
                db.execute('UPDATE users SET totp_secret = NULL WHERE id = ?',
                           (session['user_id'],))
                db.commit()
                audit_log('2fa_disable', '2FA disabled')
                flash('Two-factor authentication disabled.', 'success')
            else:
                flash('Incorrect password.', 'error')
            return redirect(url_for('setup_2fa'))

    return render_template('setup_2fa.html', has_2fa=has_2fa, step='initial')


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login') if is_auth_enabled() else url_for('index'))


# --- Page routes ---

@app.route('/')
def index():
    """Main dashboard or landing page for visitors."""
    if is_auth_enabled() and 'user_id' not in session:
        return render_template('landing.html')


    db = get_db()
    today = date.today().isoformat()
    uf, uf_params = user_filter()

    # Get or create today's journal entry
    journal = db.execute(
        f'SELECT * FROM journal_entries WHERE date = ? AND {uf}',
        (today, *uf_params)
    ).fetchone()

    # Get tags for today's entry
    journal_tags = ''
    if journal:
        tags = get_journal_tags(db, journal['id'])
        journal_tags = ', '.join(t['name'] for t in tags)

    # Get active tasks (due soonest first, then by creation)
    tasks = db.execute(
        f'''SELECT * FROM tasks WHERE completed = 0 AND {uf}
            ORDER BY priority DESC,
                     CASE WHEN due_date IS NOT NULL THEN 0 ELSE 1 END,
                     due_date ASC, created_at DESC''',
        uf_params
    ).fetchall()

    # Load subtasks for each task
    task_subtasks = {}
    for task in tasks:
        task_subtasks[task['id']] = db.execute(
            'SELECT * FROM subtasks WHERE task_id = ? ORDER BY sort_order',
            (task['id'],)
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
        # Weighted random: prefer less-surfaced and older-surfaced blips
        all_blips = db.execute(f'''
            SELECT * FROM blips WHERE {blip_uf} AND (archived = 0 OR archived IS NULL)
        ''', blip_uf_params).fetchall()
        if all_blips:
            def blip_weight(b):
                count = b['surface_count'] or 0
                weight = 1.0 / (1 + count)
                if b['last_surfaced']:
                    try:
                        last = datetime.fromisoformat(b['last_surfaced'])
                        days_ago = (datetime.now() - last).days
                        weight *= (1 + days_ago * 0.5)
                    except (ValueError, TypeError):
                        weight *= 2.0
                else:
                    weight *= 3.0  # never surfaced gets high weight
                if b['pinned']:
                    weight *= 2.0  # pinned blips surface more often
                return weight
            weights = [blip_weight(b) for b in all_blips]
            blip_count = int(get_preference(get_current_user_id(), 'daily_blip_count', '3'))
            k = min(blip_count, len(all_blips))
            daily_blips = random.choices(all_blips, weights=weights, k=k)
            # Deduplicate in case choices picks same blip
            seen = set()
            unique = []
            for b in daily_blips:
                if b['id'] not in seen:
                    seen.add(b['id'])
                    unique.append(b)
            daily_blips = unique

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

    # Dashboard stats
    total_entries = db.execute(
        f'SELECT COUNT(*) FROM journal_entries WHERE {uf}', uf_params
    ).fetchone()[0]
    total_blips = db.execute(
        f'SELECT COUNT(*) FROM blips WHERE {uf}', uf_params
    ).fetchone()[0]
    total_tasks = db.execute(
        f'SELECT COUNT(*) FROM tasks WHERE {uf}', uf_params
    ).fetchone()[0]
    completed_tasks_count = db.execute(
        f'SELECT COUNT(*) FROM tasks WHERE completed = 1 AND {uf}', uf_params
    ).fetchone()[0]
    welcome_dismissed = get_preference(get_current_user_id(), 'welcome_dismissed') == '1'
    is_new_user = (total_entries + total_blips + total_tasks) == 0 and not welcome_dismissed

    # Calculate writing streak
    streak = 0
    check_date = date.today()
    while True:
        entry = db.execute(
            f'SELECT id FROM journal_entries WHERE date = ? AND {uf}',
            (check_date.isoformat(), *uf_params)
        ).fetchone()
        if entry:
            streak += 1
            check_date -= timedelta(days=1)
        else:
            break

    return render_template('index.html',
                           journal=journal,
                           journal_tags=journal_tags,
                           tasks=tasks,
                           task_subtasks=task_subtasks,
                           blips=daily_blips,
                           today=today,
                           now=datetime.now(),
                           is_new_user=is_new_user,
                           templates=get_user_templates(get_current_user_id()),
                           stats={
                               'entries': total_entries,
                               'active_tasks': len(tasks),
                               'completed_tasks': completed_tasks_count,
                               'blips': total_blips,
                               'streak': streak,
                           })


@app.route('/dismiss-welcome', methods=['POST'])
@login_required
def dismiss_welcome():
    """Dismiss the welcome card permanently."""
    set_preference(get_current_user_id(), 'welcome_dismissed', '1')
    return redirect(url_for('index'))


@app.route('/journal/save', methods=['POST'])
@login_required
def save_journal():
    """Save journal entry."""
    today = date.today().isoformat()
    content = request.form.get('content', '')
    mood = request.form.get('mood', type=int)
    tags_str = request.form.get('tags', '')
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
            'UPDATE journal_entries SET content = ?, mood = ?, updated_at = ? WHERE id = ?',
            (content, mood, datetime.now().isoformat(), existing['id'])
        )
        entry_id = existing['id']
    else:
        cursor = db.execute(
            'INSERT INTO journal_entries (date, content, user_id, mood, updated_at) VALUES (?, ?, ?, ?, ?)',
            (today, content, user_id, mood, datetime.now().isoformat())
        )
        entry_id = cursor.lastrowid

    # Save tags
    save_journal_tags(db, entry_id, user_id, tags_str)
    db.commit()

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'saved': True})

    return redirect(url_for('index'))


@app.route('/journal/<date_str>/edit', methods=['GET', 'POST'])
@login_required
def edit_journal(date_str):
    """Edit a past journal entry."""
    db = get_db()
    uf, uf_params = user_filter()

    if request.method == 'POST':
        content = request.form.get('content', '')
        mood = request.form.get('mood', type=int)
        tags_str = request.form.get('tags', '')
        user_id = get_current_user_id()

        existing = db.execute(
            f'SELECT id FROM journal_entries WHERE date = ? AND {uf}',
            (date_str, *uf_params)
        ).fetchone()

        if existing:
            db.execute(
                'UPDATE journal_entries SET content = ?, mood = ?, updated_at = ? WHERE id = ?',
                (content, mood, datetime.now().isoformat(), existing['id'])
            )
            entry_id = existing['id']
        else:
            cursor = db.execute(
                'INSERT INTO journal_entries (date, content, user_id, mood, updated_at) VALUES (?, ?, ?, ?, ?)',
                (date_str, content, user_id, mood, datetime.now().isoformat())
            )
            entry_id = cursor.lastrowid

        save_journal_tags(db, entry_id, user_id, tags_str)
        db.commit()
        return redirect(url_for('history'))

    entry = db.execute(
        f'SELECT * FROM journal_entries WHERE date = ? AND {uf}',
        (date_str, *uf_params)
    ).fetchone()

    entry_tags = ''
    if entry:
        tags = get_journal_tags(db, entry['id'])
        entry_tags = ', '.join(t['name'] for t in tags)

    return render_template('edit_journal.html', entry=entry, entry_date=date_str, entry_tags=entry_tags)


@app.route('/tasks/add', methods=['POST'])
@login_required
def add_task():
    """Add new task."""
    title = request.form.get('title', '').strip()
    due_date = request.form.get('due_date', '').strip() or None
    priority = request.form.get('priority', 0, type=int)
    recurrence = request.form.get('recurrence', 'none')
    if recurrence not in ('none', 'daily', 'weekly', 'monthly'):
        recurrence = 'none'
    if title:
        db = get_db()
        user_id = get_current_user_id()
        db.execute('INSERT INTO tasks (title, user_id, due_date, priority, recurrence) VALUES (?, ?, ?, ?, ?)',
                   (title, user_id, due_date, min(priority, 2), recurrence))
        db.commit()

    return redirect(url_for('index'))


@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    """Edit a task's details."""
    db = get_db()
    uf, uf_params = user_filter()
    task = db.execute(f'SELECT * FROM tasks WHERE id = ? AND {uf}', (task_id, *uf_params)).fetchone()
    if not task:
        return redirect(url_for('index'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        notes = request.form.get('notes', '').strip() or None
        due_date = request.form.get('due_date', '').strip() or None
        priority = request.form.get('priority', 0, type=int)
        recurrence = request.form.get('recurrence', 'none')
        if recurrence not in ('none', 'daily', 'weekly', 'monthly'):
            recurrence = 'none'
        if title:
            db.execute(
                'UPDATE tasks SET title = ?, notes = ?, due_date = ?, priority = ?, recurrence = ? WHERE id = ?',
                (title, notes, due_date, min(priority, 2), recurrence, task_id)
            )
            db.commit()
        return redirect(url_for('index'))

    subtasks = db.execute(
        'SELECT * FROM subtasks WHERE task_id = ? ORDER BY sort_order', (task_id,)
    ).fetchall()
    return render_template('edit_task.html', task=task, subtasks=subtasks)


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

        # Auto-create next instance for recurring tasks
        if new_state and task['recurrence'] and task['recurrence'] != 'none':
            next_due = None
            base_date = date.fromisoformat(task['due_date']) if task['due_date'] else date.today()
            if task['recurrence'] == 'daily':
                next_due = (base_date + timedelta(days=1)).isoformat()
            elif task['recurrence'] == 'weekly':
                next_due = (base_date + timedelta(weeks=1)).isoformat()
            elif task['recurrence'] == 'monthly':
                month = base_date.month % 12 + 1
                year = base_date.year + (1 if month == 1 else 0)
                try:
                    next_due = base_date.replace(year=year, month=month).isoformat()
                except ValueError:
                    # Handle months with fewer days (e.g., Jan 31 -> Feb 28)
                    import calendar
                    last_day = calendar.monthrange(year, month)[1]
                    next_due = base_date.replace(year=year, month=month, day=min(base_date.day, last_day)).isoformat()
            db.execute(
                'INSERT INTO tasks (title, user_id, due_date, priority, recurrence) VALUES (?, ?, ?, ?, ?)',
                (task['title'], task['user_id'], next_due, task['priority'], task['recurrence'])
            )

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
    show = request.args.get('show', 'active')
    per_page = 50
    offset = (page - 1) * per_page

    if show == 'archived':
        blips = db.execute(
            f'SELECT * FROM blips WHERE (archived = 1) AND {uf} ORDER BY created_at DESC LIMIT ? OFFSET ?',
            (*uf_params, per_page + 1, offset)
        ).fetchall()
    elif show == 'pinned':
        blips = db.execute(
            f'SELECT * FROM blips WHERE (pinned = 1) AND (archived = 0 OR archived IS NULL) AND {uf} ORDER BY created_at DESC LIMIT ? OFFSET ?',
            (*uf_params, per_page + 1, offset)
        ).fetchall()
    else:
        blips = db.execute(
            f'SELECT * FROM blips WHERE (archived = 0 OR archived IS NULL) AND {uf} ORDER BY pinned DESC, created_at DESC LIMIT ? OFFSET ?',
            (*uf_params, per_page + 1, offset)
        ).fetchall()

    has_more = len(blips) > per_page
    blips = blips[:per_page]
    archived_count = db.execute(
        f'SELECT COUNT(*) FROM blips WHERE archived = 1 AND {uf}', uf_params
    ).fetchone()[0]
    pinned_count = db.execute(
        f'SELECT COUNT(*) FROM blips WHERE pinned = 1 AND (archived = 0 OR archived IS NULL) AND {uf}', uf_params
    ).fetchone()[0]

    return render_template('blips.html', blips=blips, page=page, has_more=has_more,
                           show=show, archived_count=archived_count, pinned_count=pinned_count)


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


@app.route('/blips/<int:blip_id>/pin', methods=['POST'])
@login_required
def pin_blip(blip_id):
    """Toggle blip pinned state."""
    db = get_db()
    uf, uf_params = user_filter()
    blip = db.execute(f'SELECT pinned FROM blips WHERE id = ? AND {uf}',
                      (blip_id, *uf_params)).fetchone()
    if blip:
        new_state = 0 if blip['pinned'] else 1
        db.execute('UPDATE blips SET pinned = ? WHERE id = ?', (new_state, blip_id))
        db.commit()
    return redirect(request.referrer or url_for('blips_list'))


@app.route('/blips/<int:blip_id>/archive', methods=['POST'])
@login_required
def archive_blip(blip_id):
    """Toggle blip archived state."""
    db = get_db()
    uf, uf_params = user_filter()
    blip = db.execute(f'SELECT archived FROM blips WHERE id = ? AND {uf}',
                      (blip_id, *uf_params)).fetchone()
    if blip:
        new_state = 0 if blip['archived'] else 1
        db.execute('UPDATE blips SET archived = ? WHERE id = ?', (new_state, blip_id))
        db.commit()
    return redirect(request.referrer or url_for('blips_list'))


@app.route('/blips/<int:blip_id>/to-task', methods=['POST'])
@login_required
def blip_to_task(blip_id):
    """Convert a blip into a task."""
    db = get_db()
    uf, uf_params = user_filter()
    blip = db.execute(f'SELECT * FROM blips WHERE id = ? AND {uf}',
                      (blip_id, *uf_params)).fetchone()
    if blip:
        user_id = get_current_user_id()
        db.execute('INSERT INTO tasks (title, user_id) VALUES (?, ?)',
                   (blip['content'][:200], user_id))
        db.commit()
        flash('Blip converted to task.', 'success')
    return redirect(url_for('blips_list'))


@app.route('/blips/bulk-add', methods=['POST'])
@login_required
def bulk_add_blips():
    """Add multiple blips at once, one per line."""
    content = request.form.get('content', '')
    user_id = get_current_user_id()
    if content:
        db = get_db()
        lines = [line.strip() for line in content.splitlines() if line.strip()]
        for line in lines:
            db.execute('INSERT INTO blips (content, user_id) VALUES (?, ?)',
                       (line, user_id))
        db.commit()
        if lines:
            flash(f'Added {len(lines)} blip{"s" if len(lines) != 1 else ""}.', 'success')
    return redirect(url_for('blips_list'))


@app.route('/history')
@login_required
def history():
    """View journal history with cross-feature integration."""
    db = get_db()
    uf, uf_params = user_filter()
    page = request.args.get('page', 1, type=int)
    from_date = request.args.get('from', '')
    to_date = request.args.get('to', '')
    tag_filter = request.args.get('tag', '')
    per_page = 30
    offset = (page - 1) * per_page

    date_filter = ''
    date_params = list(uf_params)
    if from_date:
        date_filter += ' AND date >= ?'
        date_params.append(from_date)
    if to_date:
        date_filter += ' AND date <= ?'
        date_params.append(to_date)

    if tag_filter:
        entries = db.execute(
            f'''SELECT je.* FROM journal_entries je
                JOIN journal_tags jt ON je.id = jt.journal_entry_id
                JOIN tags t ON jt.tag_id = t.id
                WHERE {uf.replace('user_id', 'je.user_id')}{date_filter.replace('date', 'je.date')}
                AND t.name = ?
                ORDER BY je.date DESC LIMIT ? OFFSET ?''',
            (*date_params, tag_filter, per_page + 1, offset)
        ).fetchall()
    else:
        entries = db.execute(
            f'SELECT * FROM journal_entries WHERE {uf}{date_filter} ORDER BY date DESC LIMIT ? OFFSET ?',
            (*date_params, per_page + 1, offset)
        ).fetchall()
    has_more = len(entries) > per_page
    entries = entries[:per_page]

    # Enrich entries with tasks completed and blips surfaced that day
    enriched = []
    for entry in entries:
        day = entry['date']
        tasks_done = db.execute(
            f"SELECT title FROM tasks WHERE completed = 1 AND DATE(completed_at) = ? AND {uf}",
            (day, *uf_params)
        ).fetchall()
        blips_surfaced = db.execute(
            f'''SELECT b.content FROM blips b
                JOIN daily_blips db ON b.id = db.blip_id
                WHERE db.journal_date = ? AND {uf.replace('user_id', 'db.user_id')}''',
            (day, *uf_params)
        ).fetchall()
        entry_tags = get_journal_tags(db, entry['id'])
        enriched.append({
            'entry': entry,
            'tasks_done': tasks_done,
            'blips_surfaced': blips_surfaced,
            'tags': entry_tags,
        })

    # Get all tags for filter dropdown
    all_tags = db.execute(
        f'SELECT DISTINCT t.name FROM tags t WHERE {uf.replace("user_id", "t.user_id")} ORDER BY t.name',
        uf_params
    ).fetchall()

    return render_template('history.html', enriched=enriched, page=page, has_more=has_more,
                           from_date=from_date, to_date=to_date, tag_filter=tag_filter,
                           all_tags=all_tags)


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
    total = db.execute(
        f'SELECT COUNT(*) FROM tasks WHERE completed = 1 AND {uf}', uf_params
    ).fetchone()[0]

    return render_template('completed_tasks.html', tasks=tasks, page=page, has_more=has_more, total=total)


@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')


@app.route('/terms')
def terms():
    """Terms of Service page."""
    return render_template('terms.html')


@app.route('/privacy')
def privacy():
    """Privacy Policy page."""
    return render_template('privacy.html')


@app.route('/api')
def api_docs():
    """API documentation."""
    return render_template('api.html')


@app.route('/settings')
@login_required
def settings():
    """Settings page."""
    user_id = get_current_user_id()
    blip_count = int(get_preference(user_id, 'daily_blip_count', '3'))
    return render_template('settings.html', version=app.config['VERSION'], blip_count=blip_count)


@app.route('/settings/preferences', methods=['POST'])
@login_required
def save_preferences():
    """Save user preferences."""
    user_id = get_current_user_id()
    blip_count = request.form.get('daily_blip_count', 3, type=int)
    blip_count = max(1, min(blip_count, 10))
    set_preference(user_id, 'daily_blip_count', blip_count)
    flash('Preferences saved.', 'success')
    return redirect(url_for('settings'))


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


@app.route('/search')
@login_required
def search():
    """Global search across journal, tasks, and blips."""
    q = request.args.get('q', '').strip()
    results = {'journal': [], 'tasks': [], 'blips': []}

    if q:
        db = get_db()
        uf, uf_params = user_filter()
        search_term = q

        # Search journal entries
        results['journal'] = db.execute(
            f'''SELECT je.* FROM journal_entries je
                JOIN journal_fts ON je.id = journal_fts.rowid
                WHERE journal_fts MATCH ? AND {uf.replace('user_id', 'je.user_id')}
                ORDER BY je.date DESC LIMIT 20''',
            (search_term, *uf_params)
        ).fetchall()

        # Search blips
        results['blips'] = db.execute(
            f'''SELECT b.* FROM blips b
                JOIN blips_fts ON b.id = blips_fts.rowid
                WHERE blips_fts MATCH ? AND {uf.replace('user_id', 'b.user_id')}
                ORDER BY b.created_at DESC LIMIT 20''',
            (search_term, *uf_params)
        ).fetchall()

        # Search tasks
        results['tasks'] = db.execute(
            f'''SELECT t.* FROM tasks t
                JOIN tasks_fts ON t.id = tasks_fts.rowid
                WHERE tasks_fts MATCH ? AND {uf.replace('user_id', 't.user_id')}
                ORDER BY t.created_at DESC LIMIT 20''',
            (search_term, *uf_params)
        ).fetchall()

    total = len(results['journal']) + len(results['tasks']) + len(results['blips'])
    return render_template('search.html', q=q, results=results, total=total)


@app.route('/export/json')
@login_required
def export_json():
    """Export all user data as JSON."""
    audit_log('export', 'JSON export')
    db = get_db()
    uf, uf_params = user_filter()

    # Journal entries with tags
    entries = db.execute(
        f'SELECT id, date, content, mood, created_at, updated_at FROM journal_entries WHERE {uf} ORDER BY date DESC',
        uf_params
    ).fetchall()
    journal_data = []
    for entry in entries:
        e = dict(entry)
        tags = get_journal_tags(db, entry['id'])
        e['tags'] = [t['name'] for t in tags]
        del e['id']
        journal_data.append(e)

    # Tasks with subtasks
    tasks = db.execute(
        f'SELECT id, title, completed, due_date, priority, recurrence, notes, created_at, completed_at FROM tasks WHERE {uf} ORDER BY created_at DESC',
        uf_params
    ).fetchall()
    tasks_data = []
    for task in tasks:
        t = dict(task)
        subtasks = db.execute(
            'SELECT title, completed FROM subtasks WHERE task_id = ? ORDER BY sort_order',
            (task['id'],)
        ).fetchall()
        t['subtasks'] = [dict(s) for s in subtasks]
        del t['id']
        tasks_data.append(t)

    data = {
        'exported_at': datetime.now().isoformat(),
        'journal_entries': journal_data,
        'tasks': tasks_data,
        'blips': [dict(r) for r in db.execute(
            f'SELECT content, pinned, archived, created_at, updated_at, surface_count FROM blips WHERE {uf} ORDER BY created_at DESC',
            uf_params
        ).fetchall()],
    }

    return Response(
        json.dumps(data, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename=casey-export-{date.today().isoformat()}.json'}
    )


@app.route('/export/csv')
@login_required
def export_csv():
    """Export all user data as CSV (zip of CSVs as a single combined CSV)."""
    audit_log('export', 'CSV export')
    db = get_db()
    uf, uf_params = user_filter()

    output = io.StringIO()
    writer = csv.writer(output)

    # Journal entries
    writer.writerow(['--- Journal Entries ---'])
    writer.writerow(['date', 'content', 'mood', 'tags', 'created_at', 'updated_at'])
    for r in db.execute(
        f'SELECT id, date, content, mood, created_at, updated_at FROM journal_entries WHERE {uf} ORDER BY date DESC',
        uf_params
    ).fetchall():
        tags = get_journal_tags(db, r['id'])
        tag_str = ', '.join(t['name'] for t in tags)
        writer.writerow([r['date'], r['content'], r['mood'] or '', tag_str, r['created_at'], r['updated_at']])

    writer.writerow([])
    writer.writerow(['--- Tasks ---'])
    writer.writerow(['title', 'completed', 'due_date', 'priority', 'recurrence', 'notes', 'created_at', 'completed_at'])
    for r in db.execute(
        f'SELECT title, completed, due_date, priority, recurrence, notes, created_at, completed_at FROM tasks WHERE {uf} ORDER BY created_at DESC',
        uf_params
    ).fetchall():
        writer.writerow([r['title'], r['completed'], r['due_date'], r['priority'], r['recurrence'], r['notes'] or '', r['created_at'], r['completed_at']])

    writer.writerow([])
    writer.writerow(['--- Blips ---'])
    writer.writerow(['content', 'pinned', 'archived', 'created_at', 'updated_at', 'surface_count'])
    for r in db.execute(
        f'SELECT content, pinned, archived, created_at, updated_at, surface_count FROM blips WHERE {uf} ORDER BY created_at DESC',
        uf_params
    ).fetchall():
        writer.writerow([r['content'], r['pinned'], r['archived'], r['created_at'], r['updated_at'], r['surface_count']])

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=casey-export-{date.today().isoformat()}.csv'}
    )


@app.route('/health')
@csrf.exempt
def health():
    """Health check endpoint."""
    try:
        db = sqlite3.connect(DATABASE)
        db.execute('SELECT 1').fetchone()
        db.close()
        return jsonify({'status': 'healthy', 'version': app.config['VERSION']}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 503


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
    audit_log('password_change', 'Password changed')
    flash('Password updated successfully.', 'success')
    return redirect(url_for('settings_account'))


@app.route('/settings/account/delete', methods=['POST'])
@login_required
def delete_account():
    """Delete user account and all associated data."""
    password = request.form.get('password', '')
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        flash('Incorrect password. Account not deleted.', 'error')
        return redirect(url_for('settings_account'))

    user_id = session['user_id']
    db.execute('DELETE FROM subtasks WHERE task_id IN (SELECT id FROM tasks WHERE user_id = ?)', (user_id,))
    db.execute('DELETE FROM daily_blips WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM blips WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM tasks WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM journal_tags WHERE journal_entry_id IN (SELECT id FROM journal_entries WHERE user_id = ?)', (user_id,))
    db.execute('DELETE FROM journal_entries WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM tags WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM user_preferences WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM api_tokens WHERE user_id = ?', (user_id,))
    audit_log('account_delete', f'Account deleted: {session.get("username")}')
    db.execute('DELETE FROM audit_log WHERE user_id = ?', (user_id,))
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    session.clear()
    return redirect(url_for('login'))


@app.route('/import/json', methods=['POST'])
@login_required
def import_json():
    """Import data from a Casey JSON export."""
    file = request.files.get('file')
    if not file or not file.filename.endswith('.json'):
        flash('Please upload a JSON file.', 'error')
        return redirect(url_for('settings'))

    try:
        data = json.load(file)
    except (json.JSONDecodeError, UnicodeDecodeError):
        flash('Invalid JSON file.', 'error')
        return redirect(url_for('settings'))

    db = get_db()
    user_id = get_current_user_id()
    imported = {'journal': 0, 'tasks': 0, 'blips': 0}

    for entry in data.get('journal_entries', []):
        existing = db.execute(
            'SELECT id FROM journal_entries WHERE date = ? AND user_id = ?',
            (entry.get('date'), user_id)
        ).fetchone()
        if not existing and entry.get('date') and entry.get('content'):
            cursor = db.execute(
                'INSERT INTO journal_entries (date, content, mood, user_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
                (entry['date'], entry['content'], entry.get('mood'), user_id,
                 entry.get('created_at', datetime.now().isoformat()),
                 entry.get('updated_at', datetime.now().isoformat()))
            )
            entry_id = cursor.lastrowid
            # Import tags if present
            for tag_name in entry.get('tags', []):
                tag_name = str(tag_name).strip()
                if not tag_name:
                    continue
                tag = db.execute('SELECT id FROM tags WHERE name = ? AND user_id = ?', (tag_name, user_id)).fetchone()
                if not tag:
                    tag_cursor = db.execute('INSERT INTO tags (name, user_id) VALUES (?, ?)', (tag_name, user_id))
                    tag_id = tag_cursor.lastrowid
                else:
                    tag_id = tag['id']
                db.execute('INSERT OR IGNORE INTO journal_tags (journal_entry_id, tag_id) VALUES (?, ?)', (entry_id, tag_id))
            imported['journal'] += 1

    for task in data.get('tasks', []):
        if task.get('title'):
            cursor = db.execute(
                'INSERT INTO tasks (title, completed, due_date, priority, recurrence, notes, user_id, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (task['title'], task.get('completed', 0), task.get('due_date'),
                 task.get('priority', 0), task.get('recurrence', 'none'), task.get('notes'),
                 user_id, task.get('created_at', datetime.now().isoformat()), task.get('completed_at'))
            )
            task_id = cursor.lastrowid
            # Import subtasks if present
            for i, sub in enumerate(task.get('subtasks', [])):
                if sub.get('title'):
                    db.execute(
                        'INSERT INTO subtasks (task_id, title, completed, sort_order) VALUES (?, ?, ?, ?)',
                        (task_id, sub['title'], sub.get('completed', 0), i)
                    )
            imported['tasks'] += 1

    for blip in data.get('blips', []):
        if blip.get('content'):
            db.execute(
                'INSERT INTO blips (content, pinned, archived, user_id, created_at, updated_at, surface_count) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (blip['content'], blip.get('pinned', 0), blip.get('archived', 0),
                 user_id, blip.get('created_at', datetime.now().isoformat()),
                 blip.get('updated_at', datetime.now().isoformat()),
                 blip.get('surface_count', 0))
            )
            imported['blips'] += 1

    db.commit()
    total = imported['journal'] + imported['tasks'] + imported['blips']
    audit_log('import', f'JSON import: {total} items ({imported["journal"]} entries, {imported["tasks"]} tasks, {imported["blips"]} blips)')
    flash(f'Imported {total} items ({imported["journal"]} entries, {imported["tasks"]} tasks, {imported["blips"]} blips).', 'success')
    return redirect(url_for('settings'))


# --- Subtasks ---

@app.route('/tasks/<int:task_id>/subtasks/add', methods=['POST'])
@login_required
def add_subtask(task_id):
    """Add a subtask to a task."""
    title = request.form.get('title', '').strip()
    db = get_db()
    uf, uf_params = user_filter()
    task = db.execute(f'SELECT id FROM tasks WHERE id = ? AND {uf}', (task_id, *uf_params)).fetchone()
    if task and title:
        max_order = db.execute('SELECT COALESCE(MAX(sort_order), 0) FROM subtasks WHERE task_id = ?',
                               (task_id,)).fetchone()[0]
        db.execute('INSERT INTO subtasks (task_id, title, sort_order) VALUES (?, ?, ?)',
                   (task_id, title, max_order + 1))
        db.commit()
    return redirect(url_for('index'))


@app.route('/subtasks/<int:subtask_id>/toggle', methods=['POST'])
@login_required
def toggle_subtask(subtask_id):
    """Toggle subtask completion."""
    db = get_db()
    uf, uf_params = user_filter()
    subtask = db.execute(
        f'SELECT s.* FROM subtasks s JOIN tasks t ON s.task_id = t.id WHERE s.id = ? AND {uf.replace("user_id", "t.user_id")}',
        (subtask_id, *uf_params)
    ).fetchone()
    if subtask:
        db.execute('UPDATE subtasks SET completed = ? WHERE id = ?',
                   (0 if subtask['completed'] else 1, subtask_id))
        db.commit()
    return redirect(url_for('index'))


@app.route('/subtasks/<int:subtask_id>/delete', methods=['POST'])
@login_required
def delete_subtask(subtask_id):
    """Delete a subtask."""
    db = get_db()
    uf, uf_params = user_filter()
    db.execute(
        f'DELETE FROM subtasks WHERE id = ? AND task_id IN (SELECT id FROM tasks WHERE {uf})',
        (subtask_id, *uf_params)
    )
    db.commit()
    return redirect(url_for('index'))


# --- Calendar View ---

@app.route('/calendar')
@login_required
def calendar_view():
    """Calendar view of journal entries."""
    db = get_db()
    uf, uf_params = user_filter()
    year = request.args.get('year', date.today().year, type=int)
    month = request.args.get('month', date.today().month, type=int)

    # Get all entries for this month
    start_date = f'{year:04d}-{month:02d}-01'
    if month == 12:
        end_date = f'{year+1:04d}-01-01'
    else:
        end_date = f'{year:04d}-{month+1:02d}-01'

    entries = db.execute(
        f'SELECT date, mood FROM journal_entries WHERE {uf} AND date >= ? AND date < ? ORDER BY date',
        (*uf_params, start_date, end_date)
    ).fetchall()
    entry_dates = {e['date']: e['mood'] for e in entries}

    # Build calendar data
    import calendar as cal
    cal_obj = cal.Calendar(firstweekday=0)  # Monday first
    weeks = cal_obj.monthdayscalendar(year, month)

    month_name = cal.month_name[month]

    # Previous/next month
    if month == 1:
        prev_year, prev_month = year - 1, 12
    else:
        prev_year, prev_month = year, month - 1
    if month == 12:
        next_year, next_month = year + 1, 1
    else:
        next_year, next_month = year, month + 1

    # Calculate journal streaks
    all_dates = db.execute(
        f'SELECT date FROM journal_entries WHERE {uf} ORDER BY date DESC',
        uf_params
    ).fetchall()
    all_date_set = {r['date'] for r in all_dates}

    current_streak = 0
    d = date.today()
    # If no entry today, start from yesterday
    if d.isoformat() not in all_date_set:
        d = d - timedelta(days=1)
    while d.isoformat() in all_date_set:
        current_streak += 1
        d = d - timedelta(days=1)

    longest_streak = 0
    if all_dates:
        sorted_dates = sorted(all_date_set)
        streak = 1
        for i in range(1, len(sorted_dates)):
            prev_d = date.fromisoformat(sorted_dates[i - 1])
            curr_d = date.fromisoformat(sorted_dates[i])
            if (curr_d - prev_d).days == 1:
                streak += 1
            else:
                longest_streak = max(longest_streak, streak)
                streak = 1
        longest_streak = max(longest_streak, streak)

    total_entries = len(all_date_set)
    entries_this_month = len(entry_dates)

    return render_template('calendar.html',
                           year=year, month=month, month_name=month_name,
                           weeks=weeks, entry_dates=entry_dates,
                           prev_year=prev_year, prev_month=prev_month,
                           next_year=next_year, next_month=next_month,
                           today=date.today().isoformat(),
                           current_streak=current_streak,
                           longest_streak=longest_streak,
                           total_entries=total_entries,
                           entries_this_month=entries_this_month)


# --- Journal Templates ---

JOURNAL_TEMPLATES = [
    {
        'name': 'Morning Pages',
        'content': "What's on my mind this morning:\n\n\nWhat I'm grateful for:\n\n\nMy intention for today:\n\n",
    },
    {
        'name': 'Weekly Review',
        'content': "## What went well this week\n\n\n## What didn't go well\n\n\n## What I learned\n\n\n## Focus for next week\n\n",
    },
    {
        'name': 'Daily Standup',
        'content': "## Done yesterday\n\n\n## Doing today\n\n\n## Blockers\n\n",
    },
    {
        'name': 'Brain Dump',
        'content': "",
    },
]


def get_user_templates(user_id):
    """Get user's custom templates, falling back to defaults."""
    custom = get_preference(user_id, 'journal_templates')
    if custom:
        try:
            return json.loads(custom)
        except (json.JSONDecodeError, TypeError):
            pass
    return JOURNAL_TEMPLATES


@app.route('/journal/templates')
@login_required
def journal_templates():
    """Get available journal templates as JSON."""
    user_id = get_current_user_id()
    return jsonify({'templates': get_user_templates(user_id)})


@app.route('/settings/templates')
@login_required
def settings_templates():
    """Journal templates management page."""
    user_id = get_current_user_id()
    templates = get_user_templates(user_id)
    return render_template('settings_templates.html', templates=templates)


@app.route('/settings/templates/save', methods=['POST'])
@login_required
def save_templates():
    """Save custom journal templates."""
    user_id = get_current_user_id()
    templates = []
    i = 0
    while True:
        name = request.form.get(f'name_{i}')
        if name is None:
            break
        content = request.form.get(f'content_{i}', '')
        if name.strip():
            templates.append({'name': name.strip(), 'content': content})
        i += 1
    if not templates:
        flash('You need at least one template.', 'error')
        return redirect(url_for('settings_templates'))
    set_preference(user_id, 'journal_templates', json.dumps(templates))
    flash('Templates saved.', 'success')
    return redirect(url_for('settings_templates'))


@app.route('/settings/templates/reset', methods=['POST'])
@login_required
def reset_templates():
    """Reset journal templates to defaults."""
    user_id = get_current_user_id()
    db = get_db()
    db.execute('DELETE FROM user_preferences WHERE user_id = ? AND key = ?',
               (user_id, 'journal_templates'))
    db.commit()
    flash('Templates reset to defaults.', 'success')
    return redirect(url_for('settings_templates'))


# --- Admin Panel ---

@app.route('/admin')
@admin_required
def admin_panel():
    """Admin dashboard."""
    db = get_db()
    stats = {
        'total_users': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'total_entries': db.execute('SELECT COUNT(*) FROM journal_entries').fetchone()[0],
        'total_tasks': db.execute('SELECT COUNT(*) FROM tasks').fetchone()[0],
        'total_blips': db.execute('SELECT COUNT(*) FROM blips').fetchone()[0],
        'active_today': db.execute(
            "SELECT COUNT(DISTINCT user_id) FROM journal_entries WHERE date = ?",
            (date.today().isoformat(),)
        ).fetchone()[0],
        'new_users_7d': db.execute(
            "SELECT COUNT(*) FROM users WHERE created_at >= datetime('now', '-7 days')"
        ).fetchone()[0],
    }

    users = db.execute('''
        SELECT u.id, u.username, u.is_admin, u.created_at,
               (SELECT COUNT(*) FROM journal_entries WHERE user_id = u.id) as entry_count,
               (SELECT COUNT(*) FROM tasks WHERE user_id = u.id) as task_count,
               (SELECT COUNT(*) FROM blips WHERE user_id = u.id) as blip_count,
               (SELECT MAX(date) FROM journal_entries WHERE user_id = u.id) as last_active
        FROM users u ORDER BY u.created_at DESC
    ''').fetchall()

    recent_audit = db.execute('''
        SELECT a.action, a.detail, a.ip_address, a.created_at,
               u.username
        FROM audit_log a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC LIMIT 50
    ''').fetchall()

    return render_template('admin.html', stats=stats, users=users, audit_log=recent_audit)


@app.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    """Toggle admin status for a user."""
    if user_id == session['user_id']:
        flash('Cannot change your own admin status.', 'error')
        return redirect(url_for('admin_panel'))
    db = get_db()
    user = db.execute('SELECT username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    if user:
        new_status = 0 if user['is_admin'] else 1
        db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_status, user_id))
        db.commit()
        audit_log('admin_toggle', f'{"Granted" if new_status else "Revoked"} admin for {user["username"]}')
        flash('Admin status updated.', 'success')
    return redirect(url_for('admin_panel'))


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
