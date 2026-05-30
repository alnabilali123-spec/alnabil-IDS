# core/user_manager.py
import json
import os
from datetime import datetime

USERS_FILE = "database/users.json"

def init_users():
    os.makedirs("database", exist_ok=True)
    if not os.path.exists(USERS_FILE):
        default_users = {
            "admin": {"password": "2005", "role": "admin", "email": "alaxhmood@gmail.com", "created": str(datetime.now())},
            "analyst": {"password": "analyst123", "role": "analyst", "email": "analyst@aegis.local", "created": str(datetime.now())}
        }
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)

def get_users():
    with open(USERS_FILE, "r") as f:
        users = json.load(f)
    return {u: {"role": d["role"], "email": d["email"]} for u, d in users.items()}

def add_user(username, password, role, email):
    users = json.load(open(USERS_FILE, "r"))
    if username in users:
        return False
    users[username] = {"password": password, "role": role, "email": email, "created": str(datetime.now())}
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    return True

def delete_user(username):
    if username == "admin":
        return False
    users = json.load(open(USERS_FILE, "r"))
    if username in users:
        del users[username]
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        return True
    return False

def update_user(username, role, email):
    users = json.load(open(USERS_FILE, "r"))
    if username in users:
        users[username]["role"] = role
        users[username]["email"] = email
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        return True
    return False

init_users()
