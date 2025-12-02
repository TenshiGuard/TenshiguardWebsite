import os
from pathlib import Path

# =========================================================
# 📦 Base Directory Setup
# =========================================================
BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
INSTANCE_DIR.mkdir(exist_ok=True)

# =========================================================
# ⚙️ Unified Configuration Class
# =========================================================
class Config:
    # =========================================================
    # 🔹 Core Application
    # =========================================================
    SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-this")

    # Database (SQLite by default)
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{INSTANCE_DIR / 'tenshiguard.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("1", "true")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB uploads
    CORS_HEADERS = "Content-Type"

    # =========================================================
    # 🔹 Mail (for alerts, password reset)
    # =========================================================
    MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() in ("1", "true")
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "False").lower() in ("1", "true")
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "TenshiGuard <noreply@tenshiguard.local>")

    # =========================================================
    # 🔹 Multi-Factor & Security
    # =========================================================
    SECURITY_TOKEN_EXPIRATION = int(os.getenv("SECURITY_TOKEN_EXPIRATION", 3600))  # 1 hour
    MFA_ENABLED = os.getenv("MFA_ENABLED", "True").lower() in ("1", "true")

    # =========================================================
    # 🔹 Alert Integrations (Twilio)
    # =========================================================
    TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
    TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
    TWILIO_FROM_NUMBER = os.getenv("TWILIO_FROM_NUMBER", "")

    # =========================================================
    # 🔹 Billing / Payment (Stripe)
    # =========================================================
    STRIPE_PUBLIC_KEY = os.getenv("STRIPE_PUBLIC_KEY", "")
    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

    # =========================================================
    # 🔹 Wazuh Integration (future live data)
    # =========================================================
    WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh")
    WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "wazuh")

    # =========================================================
    # 🔹 AI / OpenAI / Gemini Integration
    # =========================================================
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")

    # =========================================================
    # 🔹 Instance / Paths
    # =========================================================
    INSTANCE_FOLDER_PATH = str(INSTANCE_DIR)
    APP_NAME = "TenshiGuard"

