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

**Admin login:**
1. Start registering a new user through the application.
2. During registration use: `Username: admin`, this makes the role an admin role.
3. After registration, login.
4. Try visiting the admin page by replacing `/dashboard` with `/admin`.
5. **Expected Result**: "Welcome to the admin panel!" message.

### Encryption Using Session Tokens and HTTPS
To protect sensitive data, encryption is used. Passwords are protected with bcrypt as mentioned above. Further, Flask sessions are protected with: 
1. A strong secret key generated using `os.urandom(24)`, 
2. `SESSION_COOKIE_HTTPONLY=True`, blocks JavaScript from accessing session cookies.
3. `SESSION_COOKIE_SECURE=True`, cookies are only sent over HTTPS.
4. `SESSION_COOKIE_SAMESITE='Lax'`, helps mitigate Cross-Site Request Forgery (CSRF) attacks. CSRF is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated.

Finally, the app is configured to run over HTTPS using a local SSL certificate. To verify, search on your browser:
```
https://127.0.0.1:5000/
```



