# app/services/offline_sweeper.py
import threading
import time
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models.device import Device


OFFLINE_MINUTES = 5          # how long without heartbeat before marking OFFLINE
SWEEP_INTERVAL_SECONDS = 60  # how often the sweeper runs


def _utcnow():
    return datetime.now(timezone.utc)


def _sweep_once(app):
    """Mark devices offline if they haven't checked in recently."""
    with app.app_context():
        cutoff = _utcnow() - timedelta(minutes=OFFLINE_MINUTES)

        # Devices that have not been seen since cutoff AND are currently online
        stale_devices = (
            Device.query
            .filter(Device.status == "online")
            .filter(Device.last_seen < cutoff)
            .all()
        )

        if not stale_devices:
            return

        for dev in stale_devices:
            dev.status = "offline"

        db.session.commit()
        print(f"[OFFLINE_SWEEPER] Marked {len(stale_devices)} devices OFFLINE")
        

def _run_loop(app):
    """Background loop that periodically calls _sweep_once."""
    while True:
        try:
            _sweep_once(app)
        except Exception as ex:
            # Don't crash the thread, just log
            print(f"[OFFLINE_SWEEPER] Error during sweep: {ex}")
        time.sleep(SWEEP_INTERVAL_SECONDS)


def start_offline_sweeper(app):
    """
    Start the offline device sweeper once per process.

    Safe to call from create_app(); it will no-op if already started.
    """
    if getattr(app, "_offline_sweeper_started", False):
        # Already running in this process
        return

    app._offline_sweeper_started = True
    t = threading.Thread(target=_run_loop, args=(app,), daemon=True)
    t.start()
    print("[OFFLINE_SWEEPER] Started background thread")
