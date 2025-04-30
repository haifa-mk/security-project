# Overview

This project involves the development of a simple web application using Flask. The application supports user registration, login, and a basic dashboard. The initial version was intentionally designed with security flaws in order to demonstrate how common web vulnerabilities can be addressed through secure coding practices.

As part of the implementation, protection against SQL injection was applied by using parameterized SQL queries. In addition, plaintext password storage was replaced with bcrypt hashing to ensure secure handling of user credentials.

---

## Steps to Run the Application

Detailed instructions for setting up and running the application are provided in the file [`how_to_run_flask.txt`](how_to_run_flask.txt).  
All required Python packages are listed in [`requirements.txt`](requirements.txt).

---

## Instructions to Test Security Features

### SQL Injection Prevention

1. Go to the login page.
2. In the **username** field, enter the following:
```' OR '1'='1
