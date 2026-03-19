import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")

    # Upload settings
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

    # Database
    DATABASE_URL = os.getenv("DATABASE_URL")

    # Allowed file types
    ALLOWED_EXTENSIONS = {"eml", "txt", "xml"}

    # Alert system settings
    ALERT_THRESHOLD = 5
    ALERT_INTERVAL = 3600  # seconds

    # SMTP settings (for alert emails)
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

    # ML model path
    ML_MODEL_PATH = os.path.join(BASE_DIR, "ml_model.pkl")