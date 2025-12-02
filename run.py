# =========================================================
# run.py — TenshiGuard Main Entry Point
# =========================================================

# 🔹 Load environment variables from .env
from dotenv import load_dotenv
import os

load_dotenv()  # ✅ ensures .env variables (MAIL, TWILIO, etc.) are available globally

from app import create_app, db
import logging

# =========================================================
# 🔹 Create Flask App
# =========================================================
app = create_app()

# =========================================================
# 🔹 Logging Setup
# =========================================================
if not os.path.exists("logs"):
    os.mkdir("logs")

logging.basicConfig(
    filename="logs/tenshiguard.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logging.getLogger().addHandler(logging.StreamHandler())

logging.info("🚀 TenshiGuard server starting...")

# =========================================================
# 🔹 Run Application
# =========================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "False").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
