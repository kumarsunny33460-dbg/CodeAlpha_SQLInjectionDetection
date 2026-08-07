import os
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()


MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "SQLInjectionSecurity")


try:
    client = MongoClient(MONGO_URI)

    db = client[DATABASE_NAME]

    users_collection = db["SecureUsers"]
    logs_collection = db["AttackLogs"]

    print("✅ Cloud Database Connected Successfully!")

except Exception as e:
    print("❌ Database Connection Failed:", e)



# Save secure user data
def save_user(user_data):

    try:
        users_collection.insert_one(user_data)

        return True

    except Exception as e:
        print("User Save Error:", e)
        return False



# Save attack logs
def save_attack_log(log_data):

    try:

        log_data["time"] = log_data.get(
            "time",
            datetime.now()
        )

        logs_collection.insert_one(log_data)

        return True

    except Exception as e:

        print("Attack Log Error:", e)

        return False



# Fetch all users
def get_users():

    try:

        users = list(
            users_collection.find(
                {},
                {
                    "_id": 0,
                    "encrypted_password": 0
                }
            )
        )

        return users


    except Exception as e:

        print("Fetch Users Error:", e)

        return []



# Fetch attack history
def get_attack_logs():

    try:

        logs = list(
            logs_collection.find(
                {},
                {
                    "_id": 0
                }
            ).sort(
                "time",
                -1
            ).limit(10)
        )

        return logs


    except Exception as e:

        print("Fetch Logs Error:", e)

        return []