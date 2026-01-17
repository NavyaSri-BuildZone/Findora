import os


BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "Findora_secret_key_change_me")

    # ✅ Database (SQLite)
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "Findora.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ✅ Uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB max upload size

    # ✅ Email OTP (SMTP) - Fill these later for real OTP
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = True

    MAIL_USERNAME = "findora.project@gmail.com"
    MAIL_PASSWORD = "quat yzjo widz tean"
    MAIL_DEFAULT_SENDER = MAIL_USERNAME

    # Email sender
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", MAIL_USERNAME)
