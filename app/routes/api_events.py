from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from datetime import datetime, timedelta, timezone

from app.models.event import Event
from app.models.device import Device

api_events = Blueprint("api_events", __name__, url_prefix="/api/events")


# ============================================================
# 🚀 LIVE EVENTS (Last 24 Hours)
# Enriched: device name, action, message, correlation score
# ============================================================
@api_events.get("/live")
@login_required
def live_events():
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    since = datetime.now(timezone.utc) - timedelta(hours=24)

    rows = (
        Event.query.filter(Event.organization_id == org.id)
        .filter(Event.ts >= since)
        .order_by(Event.ts.desc())
        .limit(200)
        .all()
    )

    events = []
    for e in rows:

        # Device name lookup
        device_name = None
        if e.device_id:
            d = Device.query.get(e.device_id)
            device_name = d.device_name if d else None

        events.append({
            "id": e.id,
            "time": e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "severity": e.severity,
            "category": e.category or "general",
            "action": e.action or "",
            "mac": e.mac or "",
            "device": device_name or e.mac or "Unknown",
            "message": e.message or "",
            "detail": e.detail or "",
            "correlation_score": e.correlation_score or 0,
            "correlation_id": e.correlation_id,
        })

    return jsonify({"status": "ok", "events": events}), 200



# ============================================================
# 📌 GET CORRELATED EVENT GROUPS
# Groups events by correlation_id
# ============================================================
@api_events.get("/correlated")
@login_required
def correlated_events():
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    # Only fetch events that are part of correlation chains
    rows = (
        Event.query.filter(Event.organization_id == org.id)
        .filter(Event.correlation_id.isnot(None))
        .order_by(Event.correlation_id.desc(), Event.ts.asc())
        .all()
    )

    groups = {}
    for e in rows:

        if e.correlation_id not in groups:
            groups[e.correlation_id] = {
                "correlation_id": e.correlation_id,
                "score": e.correlation_score,
                "events": [],
            }

        groups[e.correlation_id]["events"].append({
            "id": e.id,
            "time": e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "severity": e.severity,
            "category": e.category,
            "action": e.action,
            "message": e.message,
            "detail": e.detail,
            "mac": e.mac,
        })

    return jsonify({
        "status": "ok",
        "count": len(groups),
        "groups": list(groups.values())
    }), 200



# ============================================================
# 📌 EVENT DETAILS (for timeline expansion UI)
# ============================================================
@api_events.get("/detail/<int:event_id>")
@login_required
def event_detail(event_id):
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    e = Event.query.filter_by(id=event_id, organization_id=org.id).first()
    if not e:
        return jsonify({"status": "error", "message": "Event not found"}), 404

    device = Device.query.get(e.device_id)

    return jsonify({
        "status": "ok",
        "event": {
            "id": e.id,
            "time": e.ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "severity": e.severity,
            "category": e.category,
            "action": e.action,
            "message": e.message,
            "detail": e.detail,
            "device": device.device_name if device else None,
            "mac": e.mac,
            "correlation_id": e.correlation_id,
            "correlation_score": e.correlation_score,
        }
    })
