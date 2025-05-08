from flask import Flask, render_template, request, redirect, session, url_for , flash, get_flashed_messages
import sqlite3
import bcrypt
import bleach
import os
import re
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)


#Extra 1: File upload config, limits file formats to avoid harmful files 
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Allowed tags and attributes for the bio field
allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'br', 'p']
allowed_attrs = {}


# Weak secret key (too simple, should be random and hidden in production)
#app.secret_key = 'supersecretkey'
app.secret_key = os.urandom(24)


#Extra 2: Rate limiting to prevent abuse of the server 
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # Prevent JS access to session cookies
    SESSION_COOKIE_SECURE=True,      # Only send over HTTPS
    SESSION_COOKIE_SAMESITE='Lax'    # Mitigate CSRF attacks
)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Failed login tracking 
failed_logins = {}

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone TEXT NOT NULL,
            age INTEGER NOT NULL,
            bio TEXT,
            role TEXT NOT NULL DEFAULT 'user',  -- Role for RBAC 
            pfp_path TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

@app.route('/', methods=['GET'])
def home():
    show_login = request.args.get('show_login')
    error = request.args.get('error')
    return render_template('home.html', show_login=show_login, error=error)

#Extra 3: Function to check if password is strong
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'\d', password)
    )

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']  
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    age = request.form['age']
    #bio = request.form['bio']  #  Collect bio from the form

    # Cleans bio input to prevent invalid html tags to prevent XSS attacks
    bio = bleach.clean(request.form['bio'], tags=allowed_tags, attributes=allowed_attrs, strip=True)
    # Check if passwords match
    if password != confirm_password:
        return redirect(url_for('home', show_signup=True, error='password_mismatch'))
   
    #Extra 3: Check if the password is strong enough before proceeding
    if not is_strong_password(password):
        # Redirects back to signup form with error message
        return redirect(url_for('home', show_signup=True, error='weak_password'))

    #Extra 4: Handle file upload and sanitize the filename to prevent directory traversal attacks 
    pfp_file = request.files['pfp']
    pfp_path = None
    if pfp_file and pfp_file.filename != '':
        filename = secure_filename(pfp_file.filename)
        pfp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        pfp_file.save(pfp_path)
        pfp_path = pfp_path.replace('\\', '/')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Check if username exists
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return redirect(url_for('home', show_signup=True, error='username_exists'))

    # Check if email exists
    c.execute("SELECT * FROM users WHERE email=?", (email,))
    if c.fetchone():
        conn.close()
        return redirect(url_for('home', show_signup=True, error='email_exists'))

    try:
        #  Vulnerable to SQL Injection: user inputs directly injected into SQL query
        # c.execute(f"INSERT INTO users (username, password, name, email, phone, age, bio, role, pfp_path) VALUES ('{username}', '{password}', '{name}', '{email}', '{phone}', '{age}', '{bio}', '{role}', '{pfp_path}')")
        # new secure code
        role = 'user'    # Assign 'user' role by default  only verified admins are promoted manually in the database
        c.execute("""
            INSERT INTO users (username, password, name, email, phone, age, bio, role, pfp_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed_password, name, email, phone, age, bio, role, pfp_path))

        
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return redirect('/')
    conn.close()
    flash("Sign-up successful!") 
    return redirect(url_for('home', show_login=True))

#Extra 5: limit login attempts to prevent brute force attack 
@limiter.limit("5 per minute") 

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    #Extra 5: limit login attempts to prevent brute force attack 
    if username in failed_logins:
        attempts, last_attempt = failed_logins[username]
        if attempts >= 3 and (datetime.now() - last_attempt).seconds < 300:
            return "Account locked due to too many failed attempts. Try again later.", 403


    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    #  Vulnerable to SQL Injection: username and password values injected directly into SQL query
    # c.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    # new secure code
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

 #  Weak session management: storing sensitive user information without validation
   # if user:
     #   session['username'] = user[1]
    #    return redirect('/dashboard')
    #else:
     #   return redirect(url_for('home', show_login=True, error='invalid'))
# new secure code
    if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
        session['username'] = user[1]
        session['role'] = user[8]
        failed_logins.pop(username, None)  # Reset on success
        return redirect('/dashboard')
    else:
        #Extra 5: If login fails, record or update the number of failed attempts along with the timestamp 
        if username in failed_logins:
            failed_logins[username] = (failed_logins[username][0] + 1, datetime.now())
        else:
            failed_logins[username] = (1, datetime.now())
        return redirect(url_for('home', show_login=True, error='invalid'))



@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')

    username = session['username']

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    #  Vulnerable to SQL Injection: username value directly injected into SQL query
    # c.execute(f"SELECT * FROM users WHERE username='{username}'")

    # new secure code
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if user:
        user_data = {
           'username': user[1],
           'name': user[3],
           'email': user[4],
           'phone': user[5],
           'age': user[6],
           'bio': user[7],
           'pfp_path': user[9] }
        return render_template('dashboard.html', user=user_data)

    else:
        return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

''' Allows access to the admin page without role checking
@app.route('/admin')
def admin():
    return "Welcome to the admin panel!"
'''
@app.route('/admin')
def admin():
    if 'role' not in session or session['role'] != 'admin': # Only allows admins to enter the page
        return "Access denied, you are not an admin!", 403
    return "Welcome to the admin panel!"

if __name__ == '__main__': # Transmits data on HTTPS
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
