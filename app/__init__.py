# ============================================================
# 🧩 TenshiGuard App Factory — Stable & Production-Safe Version
# ============================================================

import os
import time
import threading
from flask import Flask
from config import Config

from .extensions import (
    db,
    migrate,
    login_manager,
    bcrypt,
    mail,
    cors,
)

# ============================================================
# 🎯 App Factory
# ============================================================

def create_app():
    # --------------------------------------------------------
    # ✓ Initialize Flask
    # --------------------------------------------------------
    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder="templates",
        static_folder="static",
    )

    app.config.from_object(Config)
    os.makedirs(app.instance_path, exist_ok=True)

    # --------------------------------------------------------
    # ✓ Initialize Extensions
    # --------------------------------------------------------
    db.init_app(app)

    # IMPORTANT: import all models BEFORE migrate.init_app
    try:
        from app.models.user import User
        from app.models.organization import Organization
        from app.models.subscription import Subscription
        from app.models.device import Device
        from app.models.device_telemetry import DeviceTelemetry
        from app.models.alert import Alert
        from app.models.alert import Alert, AlertPreference
        from app.models.event import Event
        from app.models.ai_signal import AISignal
        from app.models.incident import Incident
    except Exception as e:
        raise RuntimeError(f"[models] failed to import models: {e}") from e

    migrate.init_app(app, db)
    bcrypt.init_app(app)
    mail.init_app(app)
    cors.init_app(app)

    # --------------------------------------------------------
    # ✓ Login Manager Setup
    # --------------------------------------------------------
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return User.query.get(int(user_id))
        except Exception:
            return None

    # --------------------------------------------------------
    # ✓ Register Blueprints — Core
    # --------------------------------------------------------

    from app.routes.auth import auth as auth_bp
    app.register_blueprint(auth_bp)
    app.logger.info("[init] loaded blueprint: auth_bp")

    from app.routes.dashboard import dashboard_bp
    app.register_blueprint(dashboard_bp)
    app.logger.info("[init] loaded blueprint: dashboard_bp")

    from app.routes.api import api_bp
    app.register_blueprint(api_bp)
    app.logger.info("[init] loaded blueprint: api_bp")

    from app.routes.api_sos import api_sos
    app.register_blueprint(api_sos)
    app.logger.info("[init] loaded blueprint: api_sos")

    from app.routes.api_ai import api_ai_bp
    app.register_blueprint(api_ai_bp)
    app.logger.info("[init] loaded blueprint: api_ai_bp")

    from app.routes.api_ai_agent import api_ai_agent_bp
    app.register_blueprint(api_ai_agent_bp)
    app.logger.info("[init] loaded blueprint: api_ai_agent_bp")

    # Optional AI Seeder
    try:
        from app.routes.api_ai_seed import api_ai_seed
        app.register_blueprint(api_ai_seed)
        app.logger.info("[init] loaded blueprint: api_ai_seed")
    except Exception as e:
        app.logger.warning(f"[init] api_ai_seed skipped: {e}")

    # --------------------------------------------------------
    # ✓ Optional Blueprints
    # --------------------------------------------------------
    optional_routes = {
        "agent_installer_bp": ("app.routes.agent_installer", ""),
        "register_flow": ("app.routes.register_flow", ""),
        "sector": ("app.routes.sector", ""),
        "alerts_bp": ("app.routes.alerts", ""),
        "api_dash": ("app.routes.api_dashboard", "/api"),
        "api_events": ("app.routes.api_events", "/api"),
    }

    for name, (mod_path, prefix) in optional_routes.items():
        try:
            mod = __import__(mod_path, fromlist=[name])
            bp = getattr(mod, name)
            app.register_blueprint(bp, url_prefix=prefix or None)
            app.logger.info(f"[init] loaded blueprint: {name}")
        except Exception as e:
            app.logger.warning(f"[init] skipped {name}: {e}")

    # --------------------------------------------------------
    # 🧠 Initialize AI Engine
    # --------------------------------------------------------
    try:
        from app.ai.services.ai_engine import AIEngine
        app.ai_engine = AIEngine(app=app)
        app.logger.info("[ai] AIEngine initialized successfully.")
    except Exception as e:
        app.ai_engine = None
        app.logger.warning(f"[ai] AIEngine not available: {e}")

    # --------------------------------------------------------
    # 🔗 Initialize Correlation Engine (Phase 2)
    # --------------------------------------------------------
    try:
        from app.ai.services.correlation_engine import CorrelationEngine

        app.correlation_engine = CorrelationEngine(app=app)
        app.logger.info("[ai] CorrelationEngine initialized successfully.")
    except Exception as e:
        app.correlation_engine = None
        app.logger.warning(f"[ai] CorrelationEngine not available: {e}")

    # --------------------------------------------------------
    # 🤖 Initialize Gemini Service (Google AI)
    # --------------------------------------------------------
    try:
        from app.ai.services.gemini_service import GeminiService
        app.gemini_service = GeminiService(app=app)
        app.logger.info("[ai] GeminiService initialized successfully.")
    except Exception as e:
        app.gemini_service = None
        app.logger.warning(f"[ai] GeminiService not available: {e}")

    # --------------------------------------------------------
    # ✓ Health Check Endpoint
    # --------------------------------------------------------
    @app.route("/healthz")
    def healthz():
        return {"ok": True, "app": "TenshiGuard"}, 200

    # --------------------------------------------------------
    # ✓ Background Sweepers
    # --------------------------------------------------------
    def start_background_tasks(app):
        try:
            from app.utils.heartbeat import sweep_offline
            from app.utils.telemetry_cleanup import cleanup_old_telemetry
        except Exception as e:
            app.logger.warning(f"[background] utils missing: {e}")
            return

        def _loop():
            time.sleep(5)
            while True:
                try:
                    with app.app_context():
                        sweep_offline(45)
                        if int(time.time()) % (6 * 3600) < 20:
                            deleted = cleanup_old_telemetry(7)
                            app.logger.info(
                                f"[telemetry-cleanup] removed {deleted} rows"
                            )
                except Exception as e:
                    app.logger.error(f"[sweeper] {e}")

                time.sleep(15)

        threading.Thread(target=_loop, daemon=True).start()

    # --------------------------------------------------------
    # ✓ Background Sweepers & Log Watcher (Skip in Testing)
    # --------------------------------------------------------
    # Check both config and env var because config might be updated after create_app
    is_testing = app.config.get("TESTING") or os.environ.get("TESTING", "").lower() == "true"
    
    if not is_testing:
        start_background_tasks(app)

        try:
            from app.utils.log_watcher import start_server_log_monitor
            start_server_log_monitor(app)
            app.logger.info("[log_watcher] initialized successfully.")
        except Exception as e:
            app.logger.warning(f"[log_watcher] not started: {e}")

    # --------------------------------------------------------
    # Return App
    # --------------------------------------------------------
    return app
