
import sqlite3
import os
import uuid
import zipfile
import shutil  # Added missing import for shutil
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash, abort
)

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
DB_PATH = 'users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize database
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0,
            is_owner INTEGER DEFAULT 0
        )
    ''')
    # invites table
    c.execute('''
        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            created_by TEXT,
            created_at TEXT
        )
    ''')
    # shares table
    c.execute('''
        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            target_user TEXT,
            path TEXT,
            can_edit INTEGER DEFAULT 0
        )
    ''')
    # external_links table
    c.execute('''
        CREATE TABLE IF NOT EXISTS external_links (
            token TEXT PRIMARY KEY,
            path TEXT,
            used INTEGER DEFAULT 0,
            created_at TEXT
        )
    ''')
    # logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            path TEXT,
            timestamp TEXT
        )
    ''')
    # requests table for sub-admin approval
    c.execute('''
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester TEXT,
            action_type TEXT,
            target TEXT,
            description TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            reviewed_by TEXT,
            reviewed_at TEXT
        )
    ''')
    conn.commit()
    # ensure owner admin exists
    c.execute("SELECT * FROM users WHERE email = ?", ("jamesmaingames401@gmail.com",))
    if not c.fetchone():
        hashed = generate_password_hash("admin123")
        c.execute("INSERT INTO users (username, email, password, is_admin, is_owner) VALUES (?, ?, ?, 1, 1)",
                  ("admin", "jamesmaingames401@gmail.com", hashed))
        conn.commit()
    conn.close()

init_db()

def log_action(user, action, path=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO logs (user, action, path, timestamp) VALUES (?, ?, ?, ?)",
              (user, action, path, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def is_admin_user():
    return session.get('is_admin', False)

def is_owner_user():
    return session.get('is_owner', False)

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('files'))

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        pw = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, email, password, is_admin, is_owner FROM users WHERE email = ? OR username = ?", (email, email))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], pw):
            session['user'] = user[1]
            session['is_admin'] = bool(user[3])
            session['is_owner'] = bool(user[4])
            return redirect(url_for('files'))
        flash("Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        code = request.form['invite'].strip()
        email = request.form['email'].strip()
        pw = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT used FROM invites WHERE code = ?", (code,))
        inv = c.fetchone()
        if not inv:
            flash("Invalid invite code")
            conn.close()
            return redirect(url_for('register'))
        if inv[0] == 1:
            flash("Invite code already used")
            conn.close()
            return redirect(url_for('register'))
        hashed = generate_password_hash(pw)
        username = email.split('@')[0]
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed))
            c.execute("UPDATE invites SET used = 1 WHERE code = ?", (code,))
            conn.commit()
            conn.close()
            flash("Registration successful. Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Email already in use")
            conn.close()
    return render_template('register.html')

# Files page with versioning
@app.route('/files', methods=['GET', 'POST'])
def files():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    user_folder = os.path.join(UPLOAD_FOLDER, user)
    versions_folder = os.path.join(user_folder, '__versions__')
    os.makedirs(user_folder, exist_ok=True)
    os.makedirs(versions_folder, exist_ok=True)

    # Handle uploads
    if request.method == 'POST':
        uploads = request.files.getlist('file')
        for u in uploads:
            if u:
                fname = u.filename
                safe_name = fname.replace("..", "").lstrip("/")
                dest = os.path.join(user_folder, safe_name)
                # If exists, version old
                if os.path.exists(dest):
                    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                    version_name = f"{safe_name}.{timestamp}"
                    os.rename(dest, os.path.join(versions_folder, version_name))
                    log_action(user, 'version_save', safe_name)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                u.save(dest)
                log_action(user, 'upload', dest)

    # List items
    items = []
    for entry in os.listdir(user_folder):
        if entry == '__versions__':
            continue
        full_path = os.path.join(user_folder, entry)
        stats = os.stat(full_path)
        if os.path.isdir(full_path):
            items.append({'name': entry, 'size': '-', 'timestamp': '', 'type': 'Folder'})
        else:
            items.append({'name': entry, 'size': stats.st_size, 'timestamp': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M'), 'type': 'File'})
    return render_template('files.html', items=items)

@app.route('/versions')
def versions():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    versions_folder = os.path.join(UPLOAD_FOLDER, user, '__versions__')
    versioned = []
    if os.path.exists(versions_folder):
        for v in os.listdir(versions_folder):
            versioned.append(v)
    return render_template('versions.html', versions=versioned)

@app.route('/download_version/<version_name>')
def download_version(version_name):
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    versions_folder = os.path.join(UPLOAD_FOLDER, user, '__versions__')
    return send_from_directory(versions_folder, version_name, as_attachment=True)

@app.route('/download/<path:filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    user_folder = os.path.join(UPLOAD_FOLDER, user)
    full_path = os.path.join(user_folder, filename)
    if not os.path.exists(full_path):
        abort(404)
    if os.path.isdir(full_path):
        zip_name = f"{uuid.uuid4()}.zip"
        zip_path = os.path.join(user_folder, zip_name)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files_list in os.walk(full_path):
                for f in files_list:
                    fpath = os.path.join(root, f)
                    arcname = os.path.relpath(fpath, user_folder)
                    zf.write(fpath, arcname)
        res = send_from_directory(user_folder, zip_name, as_attachment=True)
        os.remove(zip_path)
        log_action(user, 'download_folder', filename)
        return res
    else:
        log_action(user, 'download_file', filename)
        return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/delete', methods=['POST'])
def delete():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    filename = request.form.get('filename', '').strip()
    user_folder = os.path.join(UPLOAD_FOLDER, user)
    full_path = os.path.join(user_folder, filename)
    if os.path.exists(full_path):
        if os.path.isdir(full_path):
            shutil.rmtree(full_path)
            log_action(user, 'delete_folder', filename)
        else:
            os.remove(full_path)
            log_action(user, 'delete_file', filename)
        flash(f"Deleted {filename}")
    else:
        flash("Item not found")
    return redirect(url_for('files'))

@app.route('/rename', methods=['POST'])
def rename():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    old_name = request.form.get('old_name', '').strip()
    new_name = request.form.get('new_name', '').strip()
    user_folder = os.path.join(UPLOAD_FOLDER, user)
    old_path = os.path.join(user_folder, old_name)
    new_path = os.path.join(user_folder, new_name)
    if os.path.exists(old_path):
        os.rename(old_path, new_path)
        log_action(user, 'rename', f"{old_name} -> {new_name}")
        flash(f"Renamed to {new_name}")
    else:
        flash("Original item not found")
    return redirect(url_for('files'))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    if request.method == 'POST':
        new_email = request.form['email'].strip()
        old_pw = request.form['old_password']
        new_pw = request.form['new_password'] or None
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE email = ?", (user,))
        stored = c.fetchone()[0]
        if not check_password_hash(stored, old_pw):
            flash("Incorrect current password")
            conn.close()
            return redirect(url_for('settings'))
        c.execute("UPDATE users SET email = ? WHERE email = ?", (new_email, user))
        if new_pw:
            hashed_new = generate_password_hash(new_pw)
            c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_new, new_email))
        conn.commit()
        conn.close()
        session['user'] = new_email
        flash("Settings updated")
        return redirect(url_for('settings'))
    return render_template('settings.html', user=user)

@app.route('/family', methods=['GET', 'POST'])
def family():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        target = request.form['target'].strip()
        path = request.form['path'].strip()
        can_edit = 1 if request.form.get('edit') == 'on' else 0
        c.execute("INSERT INTO shares (owner, target_user, path, can_edit) VALUES (?, ?, ?, ?)", (user, target, path, can_edit))
        conn.commit()
        flash("Successfully shared")
    c.execute("SELECT owner, path, can_edit FROM shares WHERE target_user = ?", (user,))
    shares = c.fetchall()
    conn.close()
    return render_template('family.html', shares=shares)

@app.route('/feed')
def feed():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT action, path, timestamp FROM logs WHERE user = ? ORDER BY timestamp DESC LIMIT 50", (user,))
    actions = c.fetchall()
    conn.close()
    return render_template('feed.html', actions=actions)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user' not in session or not is_admin_user():
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT username, email, is_admin FROM users")
    users = c.fetchall()
    c.execute("SELECT code, used, created_by, created_at FROM invites")
    invites = c.fetchall()
    c.execute("SELECT user, action, path, timestamp FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]
    total_storage = 0
    for u in users:
        ufolder = os.path.join(UPLOAD_FOLDER, u[1])
        for root, dirs, files_list in os.walk(ufolder):
            for f in files_list:
                total_storage += os.path.getsize(os.path.join(root, f))
    c.execute("SELECT id, requester, action_type, target, description, created_at FROM requests WHERE status = 'pending'")
    requests = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, invites=invites, logs=logs,
                           total_users=total_users, total_storage=total_storage, requests=requests)

@app.route('/generate_invite', methods=['POST'])
def generate_invite():
    if 'user' not in session or not is_admin_user():
        abort(403)
    code = str(uuid.uuid4())
    created_by = session['user']
    created_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO invites (code, used, created_by, created_at) VALUES (?, 0, ?, ?)", (code, created_by, created_at))
    conn.commit()
    conn.close()
    flash(f"Invite code generated: {code}")
    return redirect(url_for('admin'))

@app.route('/promote_user', methods=['POST'])
def promote_user():
    if 'user' not in session or not is_admin_user():
        abort(403)
    email_to_promote = request.form.get('promote_email', '').strip()
    if not email_to_promote:
        flash("No email provided for promotion.")
        return redirect(url_for('admin'))
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin = 1 WHERE email = ?", (email_to_promote,))
    conn.commit()
    conn.close()
    log_action(session['user'], f'promote_user:{email_to_promote}')
    flash(f"User {email_to_promote} has been promoted to Admin.")
    return redirect(url_for('admin'))

@app.route('/submit_request', methods=['POST'])
def submit_request():
    if 'user' not in session or not is_admin_user():
        abort(403)
    requester = session['user']
    action_type = request.form.get('action_type', '').strip()
    target = request.form.get('target', '').strip()
    description = request.form.get('description', '').strip()
    created_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO requests (requester, action_type, target, description, created_at) VALUES (?, ?, ?, ?, ?)",
              (requester, action_type, target, description, created_at))
    conn.commit()
    conn.close()
    flash("Request submitted for review.")
    return redirect(url_for('admin'))

@app.route('/review_request/<int:req_id>/<string:decision>')
def review_request(req_id, decision):
    if 'user' not in session or not is_owner_user():
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT requester, action_type, target FROM requests WHERE id = ? AND status = 'pending'", (req_id,))
    req = c.fetchone()
    if not req:
        conn.close()
        flash("Request not found or already reviewed.")
        return redirect(url_for('admin'))
    if decision == 'approve':
        if req[1] == 'promote':
            c.execute("UPDATE users SET is_admin = 1 WHERE email = ?", (req[2],))
            log_action(session['user'], f'approved_promote:{req[2]}')
        elif req[1] == 'delete':
            c.execute("DELETE FROM users WHERE email = ?", (req[2],))
            log_action(session['user'], f'approved_delete:{req[2]}')
        c.execute("UPDATE requests SET status = 'approved', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                  (session['user'], datetime.utcnow().isoformat(), req_id))
    else:
        c.execute("UPDATE requests SET status = 'denied', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                  (session['user'], datetime.utcnow().isoformat(), req_id))
        log_action(session['user'], f'denied_request:{req_id}')
    conn.commit()
    conn.close()
    flash(f"Request {decision}.")
    return redirect(url_for('admin'))

@app.route('/external/<token>')
def external(token):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT path, used FROM external_links WHERE token = ?", (token,))
    row = c.fetchone()
    if not row or row[1] == 1:
        conn.close()
        return "Invalid or expired link", 404
    full_path = os.path.join(UPLOAD_FOLDER, row[0])
    if not os.path.exists(full_path):
        conn.close()
        return "File/folder not found", 404
    if os.path.isdir(full_path):
        zip_name = f"{uuid.uuid4()}.zip"
        zip_path = os.path.join(UPLOAD_FOLDER, zip_name)
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files_list in os.walk(full_path):
                for f in files_list:
                    fpath = os.path.join(root, f)
                    arcname = os.path.relpath(fpath, UPLOAD_FOLDER)
                    zf.write(fpath, arcname)
        res = send_from_directory(UPLOAD_FOLDER, zip_name, as_attachment=True)
        os.remove(zip_path)
    else:
        res = send_from_directory(UPLOAD_FOLDER, row[0], as_attachment=True)
    c.execute("UPDATE external_links SET used = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return res

@app.route('/notifications')
def notifications():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT action, path, timestamp FROM logs WHERE user = ? ORDER BY timestamp DESC LIMIT 50", (Note))
    notes = c.fetchall()
    conn.close()
    return render_template('notifications.html', notes=notes)

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    app.run(debug=True)
