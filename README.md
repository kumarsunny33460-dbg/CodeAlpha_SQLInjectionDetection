# 🔐 SQL Injection Detection & Secure Data Protection System

## 📌 Project Overview

**SQL Injection Detection & Secure Data Protection System** is a cloud-based cybersecurity application designed to protect sensitive user data from SQL injection attacks and unauthorized access.

The system implements a **double-layer security protocol** by combining:

* 🔍 SQL Injection Detection
* 🔑 Capability Code Verification
* 🔐 AES-Based Data Encryption
* ☁️ Secure Cloud Database Storage
* 📊 Security Monitoring Dashboard

The application detects malicious inputs, blocks suspicious requests, encrypts sensitive information, and securely stores records in a cloud database.

---

# 🚀 Key Features

## 🔍 SQL Injection Detection

* Detects common SQL injection attack patterns.
* Blocks malicious user requests automatically.
* Prevents unauthorized database manipulation.
* Stores attack attempts for monitoring.

---

## 🔐 Secure Data Encryption

* Sensitive user information is encrypted before database storage.
* Prevents direct exposure of confidential data.
* Provides an additional data protection layer.

---

## 🔑 Capability Code Authentication

* Implements an additional authorization mechanism.
* Only users with a valid capability code can access secure operations.
* Helps prevent unauthorized system access.

---

## ☁️ Cloud Database Integration

* Uses MongoDB Atlas as a cloud database.
* Stores encrypted user information securely.
* Maintains separate collections for:

  * Secure Users
  * Attack Logs

---

## 📊 Security Dashboard

The dashboard provides security monitoring with:

* 👥 Total registered users
* 🚨 Total detected attacks
* 🔐 Secure user records
* ⚠️ Attack activity logs

---

# 🛠️ Technology Stack

| Technology    | Purpose                   |
| ------------- | ------------------------- |
| Python        | Backend Programming       |
| Flask         | Web Application Framework |
| HTML5         | Frontend Structure        |
| CSS3          | UI Styling                |
| Bootstrap 5   | Responsive Design         |
| JavaScript    | Client Interaction        |
| MongoDB Atlas | Cloud Database            |
| PyMongo       | MongoDB Connection        |
| Cryptography  | Data Encryption           |
| Gunicorn      | Deployment Server         |

---

# 📂 Project Structure

```
SQLInjectionDetection/

│
├── app.py
├── database.py
├── encryption.py
├── capability.py
├── sql_detector.py
│
├── templates/
│   ├── index.html
│   └── dashboard.html
│
├── static/
│   └── style.css
│
├── requirements.txt
├── Procfile
├── .env
├── .gitignore
└── README.md
```

---

# ⚙️ Installation & Setup

## 1. Clone Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Move into project folder:

```bash
cd SQLInjectionDetection
```

---

## 2. Create Virtual Environment

```bash
python -m venv venv
```

Activate virtual environment:

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

---

## 3. Install Required Packages

```bash
pip install -r requirements.txt
```

---

# 🔑 Environment Configuration

Create a `.env` file in the project root directory.

Add the following variables:

```env
MONGO_URI=your_mongodb_connection_string

DATABASE_NAME=SQLInjectionSecurity

COLLECTION_NAME=SecureUsers

CAPABILITY_CODE=your_secret_capability_code

AES_KEY=your_generated_encryption_key
```

⚠️ **Important Security Notice**

Never upload:

* MongoDB connection URL
* AES encryption key
* Capability code
* Passwords or API keys

to GitHub.

Use environment variables for protecting sensitive information.

---

# ▶️ Running the Application

Start Flask server:

```bash
python app.py
```

Open your browser:

```
http://127.0.0.1:5000/
```

---

# 🔒 Security Workflow

```
                 User Input

                      ↓

          SQL Injection Detection

                      ↓

          Capability Code Verification

                      ↓

              AES Encryption

                      ↓

          Secure Cloud Database Storage

                      ↓

           Security Dashboard Monitoring
```

---

# 🧪 Testing Scenarios

## ✅ Normal Registration

Example:

```
Name: Sunny
Email: sunny@example.com
Password: ********
Capability Code: Valid Code
```

Result:

```
User Data Stored Securely With Encryption
```

---

## ⚠️ SQL Injection Attempt

Example:

```
' OR '1'='1
```

Result:

```
SQL Injection Attack Detected. Request Blocked.
```

---

## ❌ Invalid Capability Code

Input:

```
Wrong Security Code
```

Result:

```
Invalid Capability Code
```

---

# 📊 Dashboard Monitoring

The dashboard displays:

### User Security Data

* Username
* Email
* Encryption status
* Registration time

### Attack Monitoring

* Attack type
* Malicious input
* Attack timestamp

---

# 🚀 Deployment

The project can be deployed using cloud platforms supporting Flask applications.

Deployment requirements:

* Python runtime
* Gunicorn server
* Environment variables configured
* Cloud database connection enabled

---

# 🔮 Future Enhancements

Possible improvements:

* 🤖 Machine Learning based SQL attack detection
* 📧 Real-time security alerts
* 🔐 User authentication system
* 📈 Advanced threat analytics
* ☁️ Automated cloud deployment pipeline
* 🛡️ IP-based attack monitoring

---

# 📸 Screenshots

Add screenshots of:

1. Home Page
2. Successful Secure Registration
3. SQL Injection Detection Alert
4. Security Dashboard

---

# 👨‍💻 Author

**Sunny Kumar**

Computer Science & Engineering

---

# ⭐ Project Objective

This project demonstrates practical implementation of cybersecurity concepts:

* SQL Injection Prevention
* Secure Data Encryption
* Cloud Database Security
* Attack Monitoring
* Secure Web Application Development

---

## 🔐 Security First Approach

**Detect → Verify → Encrypt → Store → Monitor**
