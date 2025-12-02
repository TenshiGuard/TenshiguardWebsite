import os

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # =========================================================
    # 🔐 Core Security
    # =========================================================
    SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey-change-this")

    # =========================================================
    # 🗄️ Database Configuration
    # =========================================================
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "tenshiguard.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # =========================================================
    # ✉️ Mail Configuration (Adaptive)
    # =========================================================
    ENV = os.environ.get("FLASK_ENV", "development")

    if ENV == "development":
        # Local debugging with a fake SMTP server
        MAIL_SERVER = "localhost"
        MAIL_PORT = 8025
        MAIL_USE_TLS = False
        MAIL_USE_SSL = False
        MAIL_USERNAME = None
        MAIL_PASSWORD = None
        MAIL_DEFAULT_SENDER = "TenshiGuard <no-reply@tenshiguard.local>"
        
        # 🍪 Session Config for Localhost
        SESSION_COOKIE_SECURE = False
        SESSION_COOKIE_HTTPONLY = True
        SESSION_COOKIE_SAMESITE = 'Lax'

    else:
        # Production / Cloud Mode
        MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
        MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
        MAIL_USE_TLS = True
        MAIL_USE_SSL = False
        MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
        MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
        MAIL_DEFAULT_SENDER = os.environ.get(
            "MAIL_DEFAULT_SENDER",
            "TenshiGuard <no-reply@tenshiguard.com>"
        )

    # =========================================================
    # 🔐 Token & Security Settings
    # =========================================================
    SECURITY_TOKEN_EXPIRATION = int(
        os.environ.get("SECURITY_TOKEN_EXPIRATION", 3600)
    )  # 1 hour
    MFA_ENABLED = os.environ.get("MFA_ENABLED", "True").lower() in ["true", "1"]

    # =========================================================
    # 🌐 Wazuh Integration (Future Supported)
    # =========================================================
    WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
    WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh")
    WAZUH_API_PASS = os.environ.get("WAZUH_API_PASS", "wazuh")

    # =========================================================
    # 🤖 AI Dashboard API Key (NEW — Phase 2)
    # =========================================================
    # Used to authenticate backend-only endpoints like:
    #   /api/dashboard/ai/latest
    #   /api/dashboard/ai/summary
    #   /api/dashboard/ai/device/<id>
    DASHBOARD_API_KEY = os.environ.get(
        "DASHBOARD_API_KEY",
        "dev-dashboard-key-change-me"
    )

    # =========================================================
    # 🌐 Application Meta
    # =========================================================
    APP_NAME = "TenshiGuard Endpoint Security Platform"
    COMPANY_SUPPORT_EMAIL = "support@tenshiguard.com"

