import os
from datetime import datetime, timezone

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "SQLInjectionSecurity")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "SecureUsers")


if not MONGO_URI:
    raise RuntimeError(
        "MONGO_URI is missing. Please add it to your .env file."
    )


client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000
)

db = client[DATABASE_NAME]

users_collection = db[COLLECTION_NAME]
attack_logs_collection = db["AttackLogs"]


# ---------------------------------------------------------
# DATABASE CONNECTION TEST
# ---------------------------------------------------------

try:
    client.admin.command("ping")
    print("Cloud Database Connected Successfully!")
except Exception as error:
    print("MongoDB Connection Error:", error)


# ---------------------------------------------------------
# SAVE USER
# ---------------------------------------------------------

def save_user(user_data):
    return users_collection.insert_one(user_data)


# ---------------------------------------------------------
# SAVE ATTACK LOG
# ---------------------------------------------------------

def save_attack_log(payload, attack_type, source):
    log_data = {
        "payload": str(payload)[:500],
        "attack_type": attack_type,
        "source": source,
        "timestamp": datetime.now(timezone.utc)
    }

    return attack_logs_collection.insert_one(log_data)


# ---------------------------------------------------------
# DASHBOARD DATA
# ---------------------------------------------------------

def get_dashboard_data():

    total_users = users_collection.count_documents({})

    total_attacks = attack_logs_collection.count_documents({
        "attack_type": "SQL Injection Attempt"
    })

    total_unauthorized = attack_logs_collection.count_documents({
        "attack_type": "Unauthorized Access Attempt"
    })

    total_security_events = attack_logs_collection.count_documents({})

    recent_users_cursor = users_collection.find(
        {},
        {
            "name": 0,
            "email": 0,
            "password": 0
        }
    ).sort(
        "created_at",
        -1
    ).limit(8)

    recent_users = []

    for index, user in enumerate(recent_users_cursor, start=1):

        created_at = user.get("created_at")

        if created_at:
            created_at = created_at.strftime(
                "%d %b %Y, %I:%M %p"
            )
        else:
            created_at = "N/A"

        recent_users.append({
            "number": index,
            "id": str(user.get("_id")),
            "status": user.get(
                "security_status",
                "Encrypted"
            ),
            "created_at": created_at
        })

    recent_logs_cursor = attack_logs_collection.find(
        {},
        {
            "payload": 0
        }
    ).sort(
        "timestamp",
        -1
    ).limit(8)

    recent_logs = []

    for log in recent_logs_cursor:

        timestamp = log.get("timestamp")

        if timestamp:
            timestamp = timestamp.strftime(
                "%d %b %Y, %I:%M %p"
            )
        else:
            timestamp = "N/A"

        recent_logs.append({
            "attack_type": log.get(
                "attack_type",
                "Security Event"
            ),
            "source": log.get(
                "source",
                "Unknown"
            ),
            "timestamp": timestamp
        })

    return {
        "statistics": {
            "total_users": total_users,
            "sql_attacks": total_attacks,
            "unauthorized_attempts": total_unauthorized,
            "security_events": total_security_events
        },

        "recent_users": recent_users,

        "recent_logs": recent_logs
    }