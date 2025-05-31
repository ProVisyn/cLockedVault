import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
DB_PATH = 'users.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create admin user if not exists
def create_admin_user():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    email TEXT,
                    password TEXT
                )''')
    c.execute("SELECT * FROM users WHERE email = ?", ("jamesmaingames401@gmail.com",))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                  ("admin", "jamesmaingames401@gmail.com", generate_password_hash("admin123")))
        conn.commit()
    conn.close()

create_admin_user()

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['user'])
    os.makedirs(user_folder, exist_ok=True)
    files = os.listdir(user_folder)
    return render_template('dashboard.html', files=files, user=session['user'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT email, password FROM users WHERE email = ? OR username = ?", 
                  (email_or_username, email_or_username))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user[1], password):
            session['user'] = user[0]
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
