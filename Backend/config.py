import os
from pathlib import Path
from dotenv import load_dotenv

# LOAD ENVIRONMENT VARIABLES

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


# DATABASE CONFIGURATION

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "phishguard_db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))

DB_CONFIG = {
    "host": DB_HOST,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_NAME,
    "port": DB_PORT,
    "connection_timeout": 15
}

# Enable certificate verification for cloud database
if DB_HOST != "localhost" and DB_HOST != "127.0.0.1":
    DB_CONFIG.update({
        "ssl_ca": str(BASE_DIR / "ca.pem"),
        "ssl_verify_cert": True,
        "ssl_verify_identity": True
    })


# FRONTEND CORS CONFIGURATION

FRONTEND_ORIGINS = [
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://127.0.0.1:5500,http://localhost:5500"
    ).split(",")
    if origin.strip()
]


# FLASK DEBUG MODE

FLASK_DEBUG = (
    os.getenv("FLASK_DEBUG", "false").lower() == "true"
)