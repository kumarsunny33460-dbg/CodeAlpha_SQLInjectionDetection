# 🔐 SQL Injection Detection & Secure Data Protection System

<div align="center">

![Cyber Security](https://img.shields.io/badge/Cybersecurity-SQL%20Injection%20Detection-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-Flask-blue?style=for-the-badge)
![Database](https://img.shields.io/badge/Database-MongoDB%20Atlas-green?style=for-the-badge)
![Encryption](https://img.shields.io/badge/Security-AES%20Encryption-purple?style=for-the-badge)

</div>


<h3 align="center">
🛡️ Cloud-Based Cybersecurity Application for Detecting SQL Injection Attacks and Protecting Sensitive User Data
</h3>


---

# 📌 Project Overview

The **SQL Injection Detection & Secure Data Protection System** is a cloud-based cybersecurity application designed to protect sensitive user information from SQL injection attacks and unauthorized access.

The system follows a **multi-layer security protocol** by combining:


```
🔍 SQL Injection Detection

          +

🔑 Capability Code Verification

          +

🔐 AES-Based Data Encryption

          +

☁️ Secure Cloud Database Storage

          +

📊 Security Monitoring Dashboard
```


The application detects malicious inputs, blocks suspicious requests, encrypts confidential information, and securely stores records in a cloud database.


---

# 🚀 Key Features


## 🔍 SQL Injection Detection Engine

The system automatically analyzes user input and detects suspicious SQL attack patterns.

### Features:

✅ Detects common SQL injection payloads  
✅ Blocks malicious requests automatically  
✅ Prevents unauthorized database manipulation  
✅ Records attack attempts for monitoring  


---

## 🔐 Secure Data Encryption

Sensitive user information is protected before database storage.

### Security Benefits:

✅ Data encryption before storage  
✅ Prevents direct exposure of confidential information  
✅ Provides an additional security layer  
✅ Protects user credentials from unauthorized access  


---

## 🔑 Capability Code Authentication

An additional authorization mechanism is implemented for secure operations.

### Advantages:

✅ Validates authorized requests  
✅ Prevents unauthorized access attempts  
✅ Adds second-layer security verification  


---

## ☁️ Cloud Database Integration

The project uses **MongoDB Atlas** for secure cloud storage.

Database collections:


```
SQLInjectionSecurity

│
├── SecureUsers

│     ├── Username
│     ├── Email
│     ├── Encrypted Data
│     └── Registration Time


└── AttackLogs

      ├── Attack Type
      ├── User Details
      └── Timestamp
```


---

## 📊 Security Monitoring Dashboard

The dashboard provides real-time security monitoring:


### 👥 User Monitoring

- Total registered users
- Secure user records
- Encryption status


### 🚨 Attack Monitoring

- Total detected attacks
- Attack type information
- Security event logs


### 🔒 System Status

```
Security Status : ACTIVE ✅
Database Status : CONNECTED ☁️
Protection      : ENABLED 🛡️
```


---

# 🛠️ Technology Stack


| Technology | Purpose |
|------------|---------|
| Python | Backend Programming |
| Flask | Web Application Framework |
| HTML5 | Frontend Structure |
| CSS3 | User Interface Styling |
| Bootstrap 5 | Responsive Design |
| JavaScript | Client Interaction |
| MongoDB Atlas | Cloud Database |
| PyMongo | Database Connectivity |
| Cryptography | Data Encryption |
| Gunicorn | Deployment Server |


---

# 📂 Project Structure


```
SQLInjectionDetection

│
├── app.py
├── database.py
├── encryption.py
├── capability.py
├── sql_detector.py
│
├── templates
│   ├── index.html
│   └── dashboard.html
│
├── static
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


## 1️⃣ Clone Repository


```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```


Navigate into project folder:


```bash
cd SQLInjectionDetection
```


---

## 2️⃣ Create Virtual Environment


```bash
python -m venv venv
```


Activate:


### Windows

```bash
venv\Scripts\activate
```


### Linux / macOS

```bash
source venv/bin/activate
```


---

## 3️⃣ Install Dependencies


```bash
pip install -r requirements.txt
```


---

# 🔑 Environment Configuration


Create a `.env` file in the project root directory.


Example:


```env
MONGO_URI=your_mongodb_connection_string

DATABASE_NAME=SQLInjectionSecurity

COLLECTION_NAME=SecureUsers

CAPABILITY_CODE=your_secret_capability_code

AES_KEY=your_generated_encryption_key
```


⚠️ **Security Notice**

Never upload these files or values publicly:


```
❌ MongoDB Connection URL

❌ AES Encryption Key

❌ Capability Code

❌ Passwords/API Keys
```


Always use environment variables for sensitive information.


---

# ▶️ Running the Application


Start Flask server:


```bash
python app.py
```


Open browser:


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

      Capability Verification

                   ↓

          AES Encryption

                   ↓

      Cloud Database Storage

                   ↓

      Security Dashboard

```


---

# 🧪 Testing Scenarios


## ✅ Normal Registration


Example:

```
Name:
Sunny

Email:
sunny@example.com

Password:
********

Capability Code:
Valid Code
```


Result:

```
User Data Stored Securely With Encryption
```


---

## ⚠️ SQL Injection Attack


Input:

```
' OR '1'='1
```


Result:


```
SQL Injection Attack Detected.
Request Blocked.
```


---

## ❌ Invalid Capability Code


Input:

```
Wrong Security Code
```


Result:


```
Invalid Capability Code.
Access Denied.
```


---

# 🚀 Deployment


The application can be deployed on cloud platforms supporting Flask applications.


Deployment requirements:


✅ Python Runtime  
✅ Gunicorn Server  
✅ Environment Variables  
✅ Cloud Database Connection  


---

# 🔮 Future Enhancements


Future improvements:


- 🤖 Machine Learning based SQL attack detection
- 📧 Real-time security email alerts
- 🔐 Complete user authentication system
- 📈 Advanced threat analytics
- ☁️ Automated cloud deployment pipeline
- 🛡️ IP-based attack monitoring


---

# 📸 Screenshots


Add screenshots of:


1. 🏠 Home Page

2. ✅ Secure Registration Success

3. 🚨 SQL Injection Detection Alert

4. 📊 Security Dashboard



---

# 👨‍💻 Author


## Sunny Kumar

🎓 Computer Science & Engineering


Developed as part of:

**CodeAlpha Cloud Computing Internship**


---

# ⭐ Project Objective


This project demonstrates practical implementation of:


- SQL Injection Prevention
- Secure Data Encryption
- Cloud Database Security
- Attack Monitoring
- Secure Web Application Development


---

<div align="center">

## 🔐 Detect → Verify → Encrypt → Store → Monitor

### Security First Approach 🛡️

</div>