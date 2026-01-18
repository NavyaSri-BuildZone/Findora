import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # ✅ Secret Key
    SECRET_KEY = os.environ.get("SECRET_KEY", "Findora_secret_key_change_me")

    # ✅ DATABASE: Render PostgreSQL (permanent) OR Local SQLite (permanent file)
    db_url = os.environ.get("DATABASE_URL")

    # Render sometimes gives postgres:// but SQLAlchemy needs postgresql://
    if db_url and db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)

    SQLALCHEMY_DATABASE_URI = db_url or ("sqlite:///" + os.path.join(BASE_DIR, "Findora.db"))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ✅ Uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB

    # ✅ SMTP (LOCAL only)
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = True

    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME)

    # ✅ Brevo (RENDER Live only)
    BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
    FROM_EMAIL = os.environ.get("FROM_EMAIL", "findora.project@gmail.com")
