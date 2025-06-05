
import sqlite3
import os
import uuid
import zipfile
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, abort

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
DB_PATH = 'users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize DB tables if not exist
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    # Invite codes
    c.execute('''
        CREATE TABLE IF NOT EXISTS invites (
            code TEXT PRIMARY KEY,
            used INTEGER DEFAULT 0,
            created_by TEXT,
            created_at TEXT
        )
    ''')
    # Shares table
    c.execute('''
        CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT,
            target_user TEXT,
            path TEXT,
            can_edit INTEGER DEFAULT 0
        )
    ''')
    # External links table
    c.execute('''
        CREATE TABLE IF NOT EXISTS external_links (
            token TEXT PRIMARY KEY,
            path TEXT,
            used INTEGER DEFAULT 0,
            created_at TEXT
        )
    ''')
    # Activity logs
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT,
            action TEXT,
            path TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    # Ensure top admin exists
    c.execute("SELECT * FROM users WHERE email = ?", ("jamesmaingames401@gmail.com",))
    if not c.fetchone():
        hashed = generate_password_hash("admin123")
        c.execute("INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, 1)",
                  ("admin", "jamesmaingames401@gmail.com", hashed))
        conn.commit()
    conn.close()

init_db()

# Helper functions
def log_action(user, action, path=""):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO logs (user, action, path, timestamp) VALUES (?, ?, ?, ?)",
              (user, action, path, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def is_admin_user():
    return session.get('is_admin', False)

# Routes

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('files'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        pw = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, email, password, is_admin FROM users WHERE email = ? OR username = ?", (email, email))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[2], pw):
            session['user'] = user[1]
            session['is_admin'] = bool(user[3])
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
        code = request.form['invite']
        email = request.form['email']
        pw = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Check invite code
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
        # Create user
        hashed = generate_password_hash(pw)
        try:
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (email.split('@')[0], email, hashed))
            c.execute("UPDATE invites SET used = 1 WHERE code = ?", (code,))
            conn.commit()
            conn.close()
            flash("Registration successful")
            return redirect(url_for('login'))
        except:
            flash("Email already in use")
            conn.close()
    return render_template('register.html')

@app.route('/files', methods=['GET', 'POST'])
def files():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    user_folder = os.path.join(UPLOAD_FOLDER, user)
    os.makedirs(user_folder, exist_ok=True)
    # Handle file upload
    if request.method == 'POST':
        uploads = request.files.getlist('file')
        for u in uploads:
            if u:
                fname = u.filename
                secure_name = fname
                dest = os.path.join(user_folder, secure_name)
                u.save(dest)
                log_action(user, 'upload', dest)
    # List files and folders
    items = []
    for root, dirs, files_list in os.walk(user_folder):
        for f in files_list:
            fpath = os.path.join(root, f)
            rel = os.path.relpath(fpath, user_folder)
            stats = os.stat(fpath)
            items.append({
                'name': rel,
                'size': stats.st_size,
                'timestamp': datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M'),
                'type': 'File'
            })
        for d in dirs:
            dpath = os.path.join(root, d)
            rel = os.path.relpath(dpath, user_folder)
            items.append({'name': rel, 'size': '-', 'timestamp': '', 'type': 'Folder'})
        break
    return render_template('files.html', items=items)

@app.route('/download/<path:filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    user_folder = os.path.join(UPLOAD_FOLDER, user)
    # Serve file
    full_path = os.path.join(user_folder, filename)
    if os.path.isdir(full_path):
        # Zip folder
        zip_name = f"{uuid.uuid4()}.zip"
        zip_path = os.path.join(user_folder, zip_name)
        zf = zipfile.ZipFile(zip_path, 'w')
        for root, dirs, files_list in os.walk(full_path):
            for f in files_list:
                fpath = os.path.join(root, f)
                arcname = os.path.relpath(fpath, user_folder)
                zf.write(fpath, arcname)
        zf.close()
        res = send_from_directory(user_folder, zip_name, as_attachment=True)
        os.remove(zip_path)
        log_action(user, 'download', filename)
        return res
    else:
        log_action(user, 'download', filename)
        return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    if request.method == 'POST':
        new_email = request.form['email']
        old_pw = request.form['old_password']
        new_pw = request.form['new_password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # Verify old password
        c.execute("SELECT password FROM users WHERE email = ?", (user,))
        stored = c.fetchone()[0]
        if not check_password_hash(stored, old_pw):
            flash("Incorrect current password")
            conn.close()
            return redirect(url_for('settings'))
        # Update email/password
        c.execute("UPDATE users SET email = ? WHERE email = ?", (new_email, user))
        if new_pw:
            hashed = generate_password_hash(new_pw)
            c.execute("UPDATE users SET password = ? WHERE email = ?", (hashed, new_email))
        conn.commit()
        conn.close()
        session['user'] = new_email
        flash("Settings updated")
    return render_template('settings.html', user=user)

@app.route('/family', methods=['GET', 'POST'])
def family():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = session['user']
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if request.method == 'POST':
        target = request.form['target']
        path = request.form['path']
        can_edit = 1 if request.form.get('edit') == 'on' else 0
        c.execute("INSERT INTO shares (owner, target_user, path, can_edit) VALUES (?, ?, ?, ?)",
                  (user, target, path, can_edit))
        conn.commit()
        flash("Successfully shared")
    # List shared items
    c.execute("SELECT owner, path, can_edit FROM shares WHERE target_user = ?", (user,))
    shares = c.fetchall()
    conn.close()
    return render_template('family.html', shares=shares)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user' not in session or not is_admin_user():
        abort(403)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Users list
    c.execute("SELECT username, email, is_admin FROM users")
    users = c.fetchall()
    # Invites
    c.execute("SELECT code, used, created_by, created_at FROM invites")
    invites = c.fetchall()
    # Logs
    c.execute("SELECT user, action, path, timestamp FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return render_template('admin.html', users=users, invites=invites, logs=logs)

@app.route('/generate_invite', methods=['POST'])
def generate_invite():
    if 'user' not in session or not is_admin_user():
        abort(403)
    code = str(uuid.uuid4())
    created_by = session['user']
    created_at = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO invites (code, used, created_by, created_at) VALUES (?, 0, ?, ?)",
              (code, created_by, created_at))
    conn.commit()
    conn.close()
    flash(f"Invite code generated: {code}")
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
    if os.path.isdir(full_path):
        # Zip and send
        zip_name = f"{uuid.uuid4()}.zip"
        zip_path = os.path.join(UPLOAD_FOLDER, zip_name)
        zf = zipfile.ZipFile(zip_path, 'w')
        for root, dirs, files_list in os.walk(full_path):
            for f in files_list:
                fpath = os.path.join(root, f)
                arcname = os.path.relpath(fpath, UPLOAD_FOLDER)
                zf.write(fpath, arcname)
        zf.close()
        res = send_from_directory(UPLOAD_FOLDER, zip_name, as_attachment=True)
        os.remove(zip_path)
    else:
        res = send_from_directory(UPLOAD_FOLDER, row[0], as_attachment=True)
    c.execute("UPDATE external_links SET used = 1 WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return res

# Serve static files
@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
    app.run(debug=True)
