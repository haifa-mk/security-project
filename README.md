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
' OR '1'='1
```
### Password Hashing with bcrypt

The application uses the bcrypt algorithm to securely hash user passwords before storing them in the database. Bcrypt is a cryptographic hashing function designed for password security.

To verify the hashing:
1. Register a new user through the application.
2. Open the `users.db` file using DB Browser for SQLite.
3. Navigate to the `users` table and view the `password` column.
4. **Expected Result**: The stored password should appear as a long, hashed string starting with `$2b$`, confirming that bcrypt hashing is applied and passwords are not stored in plain text.
