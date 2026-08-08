from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from datetime import datetime, timezone

from sql_detector import detect_sql_injection
from capability import check_capability_code
from encryption import encrypt_data
from database import (
    save_user,
    save_attack_log,
    get_dashboard_data
)

load_dotenv()

app = Flask(__name__)

app.config["JSON_SORT_KEYS"] = False


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(silent=True) or {}

        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip()
        password = str(data.get("password", ""))
        capability_code = str(data.get("capability_code", "")).strip()

        if not name or not email or not password or not capability_code:
            return jsonify({
                "success": False,
                "type": "warning",
                "message": "Please fill in all required fields."
            }), 400

        # -------------------------------------------------
        # STEP 1: SQL INJECTION DETECTION
        # -------------------------------------------------
        fields_to_check = [name, email, password, capability_code]

        detected_payload = None

        for field in fields_to_check:
            if detect_sql_injection(field):
                detected_payload = field
                break

        if detected_payload:
            save_attack_log(
                payload=detected_payload,
                attack_type="SQL Injection Attempt",
                source="Registration Form"
            )

            return jsonify({
                "success": False,
                "type": "danger",
                "message": "SQL Injection Attack Detected. Request Blocked."
            }), 403

        # -------------------------------------------------
        # STEP 2: CAPABILITY CODE VERIFICATION
        # -------------------------------------------------
        if not check_capability_code(capability_code):
            save_attack_log(
                payload="Invalid capability code",
                attack_type="Unauthorized Access Attempt",
                source="Registration Form"
            )

            return jsonify({
                "success": False,
                "type": "warning",
                "message": "Invalid Capability Code. Access Denied."
            }), 403

        # -------------------------------------------------
        # STEP 3: AES-256 ENCRYPTION
        # -------------------------------------------------
        encrypted_name = encrypt_data(name)
        encrypted_email = encrypt_data(email)
        encrypted_password = encrypt_data(password)

        user_data = {
            "name": encrypted_name,
            "email": encrypted_email,
            "password": encrypted_password,
            "security_status": "AES-256 Encrypted",
            "created_at": datetime.now(timezone.utc)
        }

        # -------------------------------------------------
        # STEP 4: SAVE SECURELY
        # -------------------------------------------------
        save_user(user_data)

        return jsonify({
            "success": True,
            "type": "success",
            "message": "User data stored securely with AES-256 encryption."
        })

    except Exception as error:
        print("Registration Error:", error)

        return jsonify({
            "success": False,
            "type": "danger",
            "message": "An internal server error occurred."
        }), 500


@app.route("/api/dashboard")
def dashboard():
    """
    Dashboard data is loaded only when the user opens
    the Dashboard section.
    """
    try:
        dashboard_data = get_dashboard_data()

        return jsonify({
            "success": True,
            "data": dashboard_data
        })

    except Exception as error:
        print("Dashboard Error:", error)

        return jsonify({
            "success": False,
            "message": "Unable to load dashboard data."
        }), 500


@app.errorhandler(404)
def page_not_found(error):
    return jsonify({
        "success": False,
        "message": "Page not found."
    }), 404


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        "success": False,
        "message": "Internal server error."
    }), 500


if __name__ == "__main__":
    print("=" * 60)
    print("SQL INJECTION DETECTION & SECURE DATA PROTECTION SYSTEM")
    print("Developed by Sunny Kumar")
    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )