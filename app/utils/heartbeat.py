# app/utils/heartbeat.py
from datetime import datetime, timezone, timedelta
from app.models.device import Device
from app.extensions import db

def sweep_offline(threshold_seconds: int = 45):
    """
    Mark devices as offline if they haven't sent a heartbeat
    within `threshold_seconds`.
    """
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(seconds=threshold_seconds)
# app/utils/heartbeat.py
from datetime import datetime, timezone, timedelta
from app.models.device import Device
from app.extensions import db

def sweep_offline(threshold_seconds: int = 45):
    """
    Mark devices as offline if they haven't sent a heartbeat
    within `threshold_seconds`.
    """
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(seconds=threshold_seconds)

    stale_devices = Device.query.filter(
        Device.last_seen < threshold,
        Device.status == "online"
    ).all()

    if stale_devices:
        for d in stale_devices:
            d.status = "offline"
        db.session.commit()
        print(f"[sweeper] Marked {len(stale_devices)} device(s) offline.")
