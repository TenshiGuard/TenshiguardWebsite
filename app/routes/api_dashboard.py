# app/routes/api_dashboard.py
# ============================================================
#  TenshiGuard Admin Dashboard API
#  - /api/dashboard/summary
#  - /api/dashboard/failed-logins-trend
# ============================================================

from datetime import datetime, timedelta

from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func

from app.extensions import db
from app.models import Device, Event, AISignal

# This name MUST match the one used in app/__init__.py optional_routes
api_dash = Blueprint("api_dash", __name__)


# ------------------------------------------------------------
# Helper: resolve organization_id safely
# ------------------------------------------------------------
def _get_org_id():
    """
    Returns the current user's organization_id (for multi-tenant safety).
    If something is wrong, returns None.
    """
    try:
        if not current_user.is_authenticated:
            return None
        return getattr(current_user, "organization_id", None)
    except Exception:
        return None


# ------------------------------------------------------------
# GET /api/dashboard/summary
# ------------------------------------------------------------
@api_dash.route("/dashboard/summary", methods=["GET"])
@login_required
def dashboard_summary():
    """
    Returns high-level metrics for the admin dashboard:

    - total_devices
    - online_devices
    - offline_devices
    - events_24h
    - high_critical_24h
    - failed_logins_24h
    - last_threat (from AISignal if any)
    """
    org_id = _get_org_id()
    if not org_id:
        return jsonify({"ok": False, "error": "No organization context"}), 400

    now = datetime.utcnow()
    window_24h = now - timedelta(hours=24)

    # Devices
    total_devices = (
        db.session.query(func.count(Device.id))
        .filter(Device.organization_id == org_id)
        .scalar()
        or 0
    )
    online_devices = (
        db.session.query(func.count(Device.id))
        .filter(
            Device.organization_id == org_id,
            Device.status == "online",
        )
        .scalar()
        or 0
    )
    offline_devices = max(total_devices - online_devices, 0)

    # Events in last 24h
    events_24h = (
        db.session.query(func.count(Event.id))
        .filter(
            Event.organization_id == org_id,
            Event.ts >= window_24h,
        )
        .scalar()
        or 0
    )

    high_critical_24h = (
        db.session.query(func.count(Event.id))
        .filter(
            Event.organization_id == org_id,
            Event.ts >= window_24h,
            Event.severity.in_(["high", "critical"]),
        )
        .scalar()
        or 0
    )

    # Failed logins from AISignal (auth category)
    failed_logins_24h = (
        db.session.query(func.count(AISignal.id))
        .filter(
            AISignal.organization_id == org_id,
            AISignal.category == "auth",
            AISignal.ts >= window_24h,
        )
        .scalar()
        or 0
    )

    # Last AI threat (if any)
    last_threat = None
    last_signal = (
        db.session.query(AISignal)
        .filter(AISignal.organization_id == org_id)
        .order_by(AISignal.ts.desc())
        .first()
    )
    if last_signal:
        last_threat = {
            "id": last_signal.id,
            "category": last_signal.category,
            "severity": last_signal.severity,
            "rule_name": last_signal.rule_name,
            "detail": last_signal.detail,
            "risk_score": last_signal.risk_score,
            "ts": last_signal.ts.strftime("%Y-%m-%d %H:%M:%S")
            if last_signal.ts
            else None,
        }

    return jsonify(
        {
            "ok": True,
            "organization_id": org_id,
            "total_devices": total_devices,
            "online_devices": online_devices,
            "offline_devices": offline_devices,
            "events_24h": events_24h,
            "high_critical_24h": high_critical_24h,
            "failed_logins_24h": failed_logins_24h,
            "last_threat": last_threat,
        }
    )


# ------------------------------------------------------------
# GET /api/dashboard/failed-logins-trend
# ------------------------------------------------------------
@api_dash.route("/dashboard/failed-logins-trend", methods=["GET"])
@login_required
def failed_logins_trend():
    """
    Returns time-series data for failed login attempts based on AISignal.

    Response format:
    {
      "ok": true,
      "labels": ["2025-11-25 20:00", "2025-11-25 21:00", ...],
      "values": [3, 7, ...]
    }
    """
    org_id = _get_org_id()
    if not org_id:
        return jsonify({"ok": False, "error": "No organization context"}), 400

    now = datetime.utcnow()
    window_24h = now - timedelta(hours=24)

    # SQLite-friendly time bucket: by hour
    # For Postgres later we can swap to date_trunc('hour', AISignal.ts)
    rows = (
        db.session.query(
            func.strftime("%Y-%m-%d %H:00", AISignal.ts).label("bucket"),
            func.count(AISignal.id).label("count"),
        )
        .filter(
            AISignal.organization_id == org_id,
            AISignal.category == "auth",
            AISignal.ts >= window_24h,
        )
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )

    labels = [r.bucket for r in rows]
    values = [r.count for r in rows]

    return jsonify(
        {
            "ok": True,
            "organization_id": org_id,
            "labels": labels,
            "values": values,
        }
    )
