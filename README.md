# Overview

This project involves the development of a simple web application using Flask. The application supports user registration, login, and a basic dashboard. The initial version was intentionally designed with security flaws in order to demonstrate how common web vulnerabilities can be addressed through secure coding practices.

---

## Steps to Run the Application

Detailed instructions for setting up and running the application are provided in the file [`how_to_run_flask.txt`](how_to_run_flask.txt).  
All required Python packages are listed in [`requirements.txt`](requirements.txt).

---

## Instructions to Test Security Features

### SQL Injection Prevention

1. Go to the login page.
2. In the **username** field, enter the following:
```
 OR '1'='1'
```
3. **Expected Result**: Login will fail, showing that SQL injection is mitigated via parameterized queries.

---

### Password Hashing with bcrypt

The application uses the bcrypt algorithm to securely hash user passwords before storing them in the database. Bcrypt is a cryptographic hashing function designed for password security.

To verify the hashing:
1. Register a new user through the application.
2. Open the `users.db` file using DB Browser for SQLite.
3. Navigate to the `users` table and view the `password` column.
4. **Expected Result**: The stored password should appear as a long, hashed string starting with `$2b$`, confirming that bcrypt hashing is applied and passwords are not stored in plain text.

### Cross-Site Scripting (XSS) Protection Using Input Sanitization

The application uses the bleach library to sanitize user-generated HTML content (e.g., the user bio) before storing or displaying it. This prevents malicious scripts from being injected and executed in the browser.

To verify XSS protection:
1. Start registering a new user through the application.
2. During registration, in the bio field, enter a script tag like:
```
<script>alert("You have been hacked!!")</script>
```
3. Submit the registration form.
4. After registration, login.
5.  **Expected Result**: The JavaScript alert should not run, and the <script> tag will be displayed as regular text.

### Role-Based Access Control (RBAC)

The application implements RBAC to control access to specific parts of the system based on a user’s role (admin or user), as stored in the database. This prevents unauthorized users from accessing sensitive routes like the admin panel.

To verify RBAC:

**User login:**
1. Start registering a new user through the application.
2. After registration, login.
3. Try visiting the admin page by replacing `/dashboard` with `/admin`.
4. **Expected Result**: "Access denied, you are not an admin!" message with a 403 error.

## 🔐 Admin Login Setup

By default, all users who register through the application are assigned the role `"user"` for security reasons.  

### ✅ How to Promote a User to Admin

To grant admin privileges to a trusted user, manually update their role in the database after registration.

#### 📌 Step-by-step:

1. Register the user normally through the application.
2. After registration, manually update the user's role to `'admin'`.

#### 💻 Example (Python):

```python
import sqlite3
conn = sqlite3.connect('users.db')
c = conn.cursor()
c.execute("UPDATE users SET role='admin' WHERE username='admin_haifa'")
conn.commit()
conn.close()
```
Replace 'admin_haifa' with the actual username of the user you want to promote.

3. Sign in.
4. Try visiting the admin page by replacing /dashboard with /admin.
5. **Expected Result**: "Welcome to the admin panel!" message. change to reprent changes]



### Encryption Using Session Tokens and HTTPS
To protect sensitive data, encryption is used. Passwords are protected with bcrypt as mentioned above. Further, Flask sessions are protected with: 
1. A strong secret key generated using `os.urandom(24)`, 
2. `SESSION_COOKIE_HTTPONLY=True`, blocks JavaScript from accessing session cookies.
3. `SESSION_COOKIE_SECURE=True`, cookies are only sent over HTTPS.
4. `SESSION_COOKIE_SAMESITE='Lax'`, helps mitigate Cross-Site Request Forgery (CSRF) attacks. CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated.

The app is configured to run over HTTPS using a local SSL certificate. To verify, search on your browser:
```
https://127.0.0.1:5000/
```

## Additional Enhancements ✨

### Login Attempt Limiting to Prevent Brute Force Attack

The application tracks login attempts and temporarily blocks IP addresses or accounts after a set number of failed login attempts. This helps prevent brute force attacks and password guessing.

### Request Rate Limiting

To prevent abuse such as spamming or denial of service (DoS) attacks, the server enforces rate limits using Flask-Limiter. Each IP is limited to:
- **50 requests per hour**
- **200 requests per day**

Exceeding this limit results in an error.

### Strong Password Enforcement

Users must choose strong passwords (minimum length of 8, use of uppercase and numbers). This mitigates the risk of account compromise through password guessing or dictionary attacks.

### Profile Picture Upload with Secure Handling

To protect the server and users, file uploads are restricted to safe types (`.gif`, `.jpg`, `.png`, `.jpeg`). Unsupported formats are rejected.
In addition:
- File names are sanitized using `werkzeug.utils.secure_filename()` to prevent directory traversal and overwriting system files.
- Uploaded files are stored in a safe, non-public directory.

To test:
1. Register and upload an image file.
2. Confirm that the image displays on your dashboard.
   
---
