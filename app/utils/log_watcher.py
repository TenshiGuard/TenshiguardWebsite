# app/utils/log_watcher.py
import os
import time
from datetime import datetime, timezone
from flask import current_app
from app.extensions import db
from app.models import Event, Organization

# Only log these specific failure patterns (most accurate)
FAIL_PATTERNS = (
    "authentication failure",       # PAM
    "Failed password for",          # SSH
)

# Ignore noise lines
IGNORE_PATTERNS = (
    "session opened",
    "session closed",
    "TTY=",
    "COMMAND=",
)


def _is_real_failed_login(line: str) -> bool:
    """Return True only for REAL failed login attempts."""
    if not line:
        return False

    text = line.lower()

    # Required: must contain at least 1 real fail keyword
    if not any(p in text for p in FAIL_PATTERNS):
        return False

    # Ignore noise lines that appear during sudo or session transitions
    if any(p in text for p in IGNORE_PATTERNS):
        return False

    return True


def start_server_log_monitor(app):
    """Monitor server auth logs for REAL failed login attempts."""
    def _loop():
        with app.app_context():
            log_files = [
                "/var/log/auth.log",
                "/var/log/secure",
                "/var/log/syslog",
            ]
            log_path = next((p for p in log_files if os.path.exists(p)), None)

            if not log_path:
                current_app.logger.warning("[Watcher] No auth log found.")
                return

            current_app.logger.info(f"[Watcher] Monitoring {log_path}")

            last_timestamp = None  # Prevent duplicates for same event

            try:
                with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(0, os.SEEK_END)  # Start from end

                    while True:
                        line = f.readline()
                        if not line:
                            time.sleep(1)
                            continue

                        if not _is_real_failed_login(line):
                            continue

                        timestamp = line[:19]  # Example: 2025-11-13T09:55...
                        detail = line.strip()

                        # Prevent duplicate event generation
                        if timestamp == last_timestamp:
                            continue
                        last_timestamp = timestamp

                        current_app.logger.warning(
                            f"[Watcher] 🚨 REAL failed login: {detail}"
                        )

                        org = Organization.query.first()
                        if not org:
                            continue

                        ev = Event(
                            organization_id=org.id,
                            mac="server-local",
                            category="auth",
                            action="failed_login",
                            detail=(
                                f"{detail} | Mitigation: Check SSH logs, "
                                f"block offending IPs, enable Fail2Ban, "
                                f"and enforce key-based auth."
                            ),
                            severity="medium",
                            ts=datetime.now(timezone.utc),
                        )
                        db.session.add(ev)
                        db.session.commit()

                        current_app.logger.info(
                            f"[Watcher] Logged failed-login event for org {org.id}"
                        )

            except Exception as e:
                current_app.logger.error(f"[Watcher] Error: {e}")

    import threading
    threading.Thread(target=_loop, daemon=True).start()
