from flask import Flask, render_template, request, jsonify
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


@app.route("/")
def home():
    users = get_users()
    logs = get_attack_logs()

    total_users = len(users)
    total_attacks = len(logs)

    return render_template(
        "index.html",
        users=users,
        logs=logs,
        total_users=total_users,
        total_attacks=total_attacks
    )


@app.route("/register", methods=["POST"])
def register():

    name = request.form.get("name")
    email = request.form.get("email")
    password = request.form.get("password")
    capability_code = request.form.get("capability_code")


    user_input = f"{name} {email} {password}"


    # SQL Injection Detection Layer
    if detect_sql_injection(user_input):

        attack_data = {
            "name": name,
            "email": email,
            "attack_type": "SQL Injection Attempt",
            "time": datetime.now()
        }

        save_attack_log(attack_data)

        return jsonify({
            "status": "danger",
            "message": "SQL Injection Attack Detected! Request Blocked."
        })


    # Capability Code Verification Layer
    if not check_capability_code(capability_code):

        attack_data = {
            "name": name,
            "email": email,
            "attack_type": "Invalid Capability Code Attempt",
            "time": datetime.now()
        }

        save_attack_log(attack_data)

        return jsonify({
            "status": "warning",
            "message": "Invalid Capability Code. Access Denied."
        })


    # AES Encryption Layer
    encrypted_password = encrypt_data(password)


    user_data = {
        "name": name,
        "email": email,
        "encrypted_password": encrypted_password,
        "security": "AES-256 Encrypted",
        "created_at": datetime.now()
    }


    save_user(user_data)


    return jsonify({
        "status": "success",
        "message": "User Registered Successfully With AES-256 Encryption."
    })


@app.route("/api/stats")
def stats():

    users = get_users()
    logs = get_attack_logs()

    return jsonify({

        "total_users": len(users),
        "total_attacks": len(logs),
        "security_status": "ACTIVE"

    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )