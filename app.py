from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import bcrypt
import bleach
import os

# Allowed tags and attributes for the bio field
allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'br', 'p']
allowed_attrs = {}


app = Flask(__name__)

# Weak secret key (too simple, should be random and hidden in production)
#app.secret_key = 'supersecretkey'
app.secret_key = os.urandom(24)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,    # Prevent JS access to session cookies
    SESSION_COOKIE_SECURE=True,      # Only send over HTTPS
    SESSION_COOKIE_SAMESITE='Lax'    # Mitigate CSRF attacks
)

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,  --  Password stored as plain text (no hashing)
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            age INTEGER NOT NULL,
            bio TEXT,
            role TEXT NOT NULL DEFAULT 'user'  -- Role for RBAC 
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

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    name = request.form['name']
    email = request.form['email']
    phone = request.form['phone']
    age = request.form['age']
    #bio = request.form['bio']  #  Collect bio from the form

    # Cleans bio input to prevent invalid html tags to prevent XSS attacks
    bio = bleach.clean(request.form['bio'], tags=allowed_tags, attributes=allowed_attrs, strip=True)

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        #  Vulnerable to SQL Injection: user inputs directly injected into SQL query
        #c.execute(f"INSERT INTO users (username, password, name, email, phone, age, bio) VALUES ('{username}', '{password}', '{name}', '{email}', '{phone}', '{age}', '{bio}')")
        # new secure code
        role = 'admin' if username == 'admin' else 'user' 

        c.execute("""
            INSERT INTO users (username, password, name, email, phone, age, bio, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, hashed_password, name, email, phone, age, bio, role))

        
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return redirect('/')
    conn.close()

    return redirect(url_for('home', show_login=True))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

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
        return redirect('/dashboard')
    else:
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
        return render_template('dashboard.html',
                               username=user[1],
                               name=user[3],
                               email=user[4],
                               phone=user[5],
                               age=user[6],
                               bio=user[7]) 
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
