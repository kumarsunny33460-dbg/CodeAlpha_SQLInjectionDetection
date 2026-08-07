from flask import Flask, render_template, request, redirect, url_for
from dotenv import load_dotenv
from datetime import datetime

from sql_detector import detect_sql_injection
from capability import check_capability_code
from encryption import encrypt_data
from database import (
    save_user,
    save_attack_log,
    get_users,
    get_attack_logs
)

load_dotenv()

app = Flask(__name__)

app.secret_key = "SQLSECURE2026"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():

    try:
        name = request.form.get("name", "")
        email = request.form.get("email", "")
        password = request.form.get("password", "")
        capability_code = request.form.get("capability_code", "")


        # SQL Injection Detection
        if detect_sql_injection(name) or detect_sql_injection(email):

            save_attack_log({
                "type": "SQL Injection Attempt",
                "input": f"{name} {email}",
                "time": datetime.now()
            })

            return render_template(
                "index.html",
                message="⚠️ SQL Injection Attack Detected. Request Blocked."
            )


        # Capability Code Verification
        if not check_capability_code(capability_code):

            save_attack_log({
                "type": "Invalid Capability Code",
                "input": capability_code,
                "time": datetime.now()
            })

            return render_template(
                "index.html",
                message="❌ Invalid Capability Code."
            )


        # AES Encryption
        encrypted_password = encrypt_data(password)


        user_data = {
            "name": name,
            "email": email,
            "password": encrypted_password,
            "security": "AES-256 Encrypted",
            "created_at": datetime.now()
        }


        save_user(user_data)


        return render_template(
            "index.html",
            message="✅ User Data Stored Securely With AES-256 Encryption."
        )


    except Exception as e:

        return render_template(
            "index.html",
            message=f"Server Error: {str(e)}"
        )



@app.route("/dashboard")
def dashboard():

    try:

        users = get_users()
        attacks = get_attack_logs()


        total_users = len(users)
        total_attacks = len(attacks)


        return render_template(
            "dashboard.html",
            users=users,
            attacks=attacks,
            total_users=total_users,
            total_attacks=total_attacks
        )


    except Exception as e:

        return f"Dashboard Error: {e}"



if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )