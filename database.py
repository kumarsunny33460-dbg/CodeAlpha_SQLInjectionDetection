import os
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()


MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "SQLInjectionSecurity")


client = MongoClient(MONGO_URI)

db = client[DATABASE_NAME]


users_collection = db["SecureUsers"]

attack_logs_collection = db["AttackLogs"]



def save_user(user):

    users_collection.insert_one(user)



def save_attack_log(log):

    attack_logs_collection.insert_one(log)



def get_users():

    users = list(
        users_collection.find(
            {},
            {
                "_id": 0,
                "password": 0
            }
        )
    )

    return users



def get_attack_logs():

    logs = list(
        attack_logs_collection.find(
            {},
            {
                "_id": 0
            }
        ).sort(
            "time",
            -1
        )
    )

    return logs



def get_database_status():

    try:

        client.admin.command("ping")

        return True

    except Exception:

        return False