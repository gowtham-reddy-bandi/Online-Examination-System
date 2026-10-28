# Online Examination System

A web-based examination platform developed using HTML, CSS, JavaScript, Node.js, Express.js, and MongoDB. The system supports student registration and login, subject and question management, online examinations, automatic evaluation, and result tracking.

## Features

* **Authentication:** Student registration, login, logout, and session management.
* **Role-based access:** Separate permissions for administrators and students.
* **Subject management:** Create and manage subjects.
* **Question bank:** Add, edit, and delete examination questions.
* **Exam management:** Create examinations and configure start times and question counts.
* **Online examinations:** Attempt examinations through a browser-based interface.
* **Question shuffling:** Questions are shuffled per student, with the order retained for that student's exam.
* **Answer saving:** Students can save and update answers before final submission.
* **Timer management:** Examination start times and deadlines are maintained server-side.
* **Automatic evaluation:** Answers are evaluated on the server when an examination is submitted.
* **Results:** Store examination results and rank students by marks.
* **Security:** Password hashing with `bcryptjs`; correct answers are not sent to student-facing responses.

## Technology Stack

| Component                   | Technology              |
| --------------------------- | ----------------------- |
| Frontend                    | HTML5, CSS3, JavaScript |
| Backend                     | Node.js, Express.js     |
| Database                    | MongoDB                 |
| MongoDB driver              | `mongodb`               |
| Authentication and sessions | Express sessions        |
| Password hashing            | `bcryptjs`              |
| Configuration               | `dotenv`                |
| Package management          | npm                     |

## Project Structure

```text
Online-Examination-System/
├── index.html          # Frontend HTML, CSS, and JavaScript
├── server.js           # Express APIs, sessions, database access, evaluation
├── package.json        # Dependencies and start scripts
├── package-lock.json   # Locked dependency versions
├── .env.example        # Example local configuration
├── .gitignore          # Excludes secrets and generated files
└── README.md           # Project documentation
```

## Prerequisites

Install the following before running the application:

* Node.js and npm
* MongoDB Community Server
* A modern web browser

## Run Locally

### 1. Start MongoDB

Make sure MongoDB Community Server is running on your computer.

### 2. Install dependencies

Open a terminal in the project directory and run:

```bash
npm install
```

If PowerShell blocks the `npm` script, use:

```powershell
npm.cmd install
```

### 3. Configure environment variables

Copy `.env.example` to `.env`.

Set the required configuration values in `.env`, including a unique, strong `SESSION_SECRET`. Configure `MONGO_URI` and other variables according to your local setup.

**Never commit `.env` or publish credentials, passwords, or session secrets.**

### 4. Start the server

```bash
node server.js
```

### 5. Open the application

Visit:

http://localhost:3000

## Create an Administrator Account

Registration intentionally creates student accounts only.

1. Register a student account through the application.
2. Open `mongosh`.
3. Run the following commands, replacing the example email with your registered email address.

```javascript
use online_examination_system

db.users.updateOne(
  { email: "your-email@example.com" },
  { $set: { role: "Admin" } }
)
```

4. Log out and log in again so the new role is reflected in the session.

**Security note:** Perform this administrative database operation only in your own development environment.

## Examination Workflow

1. The administrator creates subjects and adds questions to the question bank.
2. The administrator configures examinations.
3. Students log in and select an available examination.
4. Questions are presented in a shuffled order retained for that student's exam.
5. Students answer questions and save their responses.
6. The server enforces the examination deadline and evaluates answers upon submission.
7. The submitted attempt is locked, and the result is stored in MongoDB.

## Security Considerations

* Passwords are hashed using `bcryptjs`.
* Authentication is managed using server-side sessions.
* Protected routes enforce role-based access.
* Correct answers are not included in student-facing question responses.
* Examination deadlines are maintained server-side.
* Final evaluation occurs on the server.
* Duplicate submissions are restricted by the application's submission logic and database constraints.

For production deployment, configure HTTPS, a strong session secret, a persistent session store, appropriate database access controls, and secure cookie settings.

## Current Limitations

* A separate Faculty role is not implemented.
* Exportable administrative reports are not included in the delivered version.
* Production deployment and security hardening require additional configuration.

## Academic Project

**Project:** Online Examination System
**Problem/Project ID:** P18
**Course:** SWE3002 — Software Project Management
**Institution:** VIT-AP University

Developed as an academic project to demonstrate web application development, database integration, authentication, examination management, and server-side evaluation.
