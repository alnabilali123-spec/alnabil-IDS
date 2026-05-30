import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.absolute()
MODELS_DIR = BASE_DIR / "models"

EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "alaxhmood@gmail.com",
    "password": "safh xamu psgh rqgb",
    "alert_email": "alaxhmood@gmail.com",
    "from_name": "AEGIS-ADS Security",
    "developer": "Mohammed Bilal"
}

SECRET_KEY = "AEGIS_SECRET_KEY_2025"
ALGORITHM = "HS256"
