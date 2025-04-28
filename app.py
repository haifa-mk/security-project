from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3

app = Flask(__name__)
# ❌ Weak secret key (too simple, should be random and hidden in production)
app.secret_key = 'supersecretkey'

# Initialize database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,  -- ❌ Password stored as plain text (no hashing)
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            age INTEGER NOT NULL,
            bio TEXT  -- ❌ No input sanitization on bio field (XSS possible)
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
    bio = request.form['bio']  # ✅ Collect bio from the form

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        # ❌ Vulnerable to SQL Injection: user inputs directly injected into SQL query
        c.execute(f"INSERT INTO users (username, password, name, email, phone, age, bio) VALUES ('{username}', '{password}', '{name}', '{email}', '{phone}', '{age}', '{bio}')")
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
    # ❌ Vulnerable to SQL Injection: username and password values injected directly into SQL query
    c.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    user = c.fetchone()
    conn.close()

    if user:
        # ❌ Weak session management: storing sensitive user information without validation
        session['username'] = user[1]
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
    # ❌ Vulnerable to SQL Injection: username value directly injected into SQL query
    c.execute(f"SELECT * FROM users WHERE username='{username}'")
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
