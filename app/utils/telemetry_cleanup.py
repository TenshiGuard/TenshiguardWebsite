# app/utils/telemetry_cleanup.py

from datetime import datetime, timedelta, timezone
from app.models.device_telemetry import DeviceTelemetry   # FIXED IMPORT
from app.extensions import db

def cleanup_old_telemetry(days: int = 7):
    """
    Delete telemetry older than N days to prevent DB bloat.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    old_records = DeviceTelemetry.query.filter(
        DeviceTelemetry.ts < cutoff
    )

    deleted = old_records.delete()
    db.session.commit()
    return deleted
