
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

users = {
    "admin@clockedvault.com": {
        "password": "changeme123",
        "role": "admin"
    }
}
invite_codes = {"INVITE123": True}

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
        email = request.form['email']
        password = request.form['password']
        if email in users and users[email]['password'] == password:
            session['user'] = email
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        invite_code = request.form['invite']
        email = request.form['email']
        password = request.form['password']
        if invite_code in invite_codes and invite_codes[invite_code]:
            users[email] = {"password": password, "role": "user"}
            invite_codes[invite_code] = False
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    file = request.files['file']
    if file:
        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['user'])
        os.makedirs(user_folder, exist_ok=True)
        file.save(os.path.join(user_folder, filename))
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('login'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], session['user'])
    return send_from_directory(user_folder, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
