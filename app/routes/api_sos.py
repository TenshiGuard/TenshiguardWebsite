# ============================================================
# ⚙️ SOS ALERT MANAGEMENT (LIVE + PREFS + CRITICAL TRIGGERS)
# ============================================================
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user

from app.extensions import db
from app.models.alert import Alert, AlertPreference
from app.models.event import Event
from app.services.alerting_service import maybe_send_alert
from app.security.permissions import role_required

# ============================================================
# 🔹 BLUEPRINT SETUP
# ============================================================
api_sos = Blueprint("api_sos", __name__, url_prefix="/api/sos")


# ============================================================
# 🔹 HELPER: Mitigation Recommendations
# ============================================================
def mitigation_hint(event: Event) -> str:
    """Return a recommended mitigation tip for each event type."""
    sev = (event.severity or "").lower()
    cat = (event.category or "").lower()
    act = (event.action or "").lower()

    if act == "failed_login":
        return "Check authentication logs and enable fail2ban or MFA."
    if cat == "malware":
        return "Isolate endpoint and perform a full antivirus scan."
    if cat == "network":
        return "Review firewall rules and restrict suspicious IP traffic."
    if sev == "critical":
        return "Immediate administrator action required."
    if act == "registered":
        return "Verify the new host identity and baseline configuration."
    return "Monitor for recurrence or repeated activity."


def _iso_utc(ts: datetime | None) -> str | None:
    """Ensure ISO8601 UTC format (fixes Invalid Date in JS)."""
    if not ts:
        return None
    s = ts.isoformat()
    return s.replace("+00:00", "Z")


# ============================================================
# 🔹 CORE: Build the last-24h alert payload
# ============================================================
def _build_latest_payload(org_id: int) -> dict:
    """Internal helper to build the common 'alerts' JSON structure."""
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=24)

    events = (
        Event.query
        .filter(Event.organization_id == org_id)
        .filter(Event.ts >= since)
        .filter(Event.category.in_(["auth", "agent", "malware", "network", "system"]))
        .filter(Event.severity.in_(["info", "low", "medium", "high", "critical"]))
        .order_by(Event.ts.desc())
        .limit(50)
        .all()
    )

    data = []
    for e in events:
        data.append({
            "time": _iso_utc(e.ts),
            "severity": (e.severity or "info").lower(),
            "category": e.category or "general",
            "action": e.action or "",
            "mac": e.mac or "",
            "detail": e.detail or "",
            "mitigation": mitigation_hint(e),
        })

    return {"status": "ok", "alerts": data}


# ============================================================
# 🔹 LIVE ALERT FEED (Last 24h) — MAIN ENDPOINT
# ============================================================
@api_sos.get("/latest")
@login_required
def latest_alerts():
    """
    Return the last 24 hours of agent/security events for the user's organization.
    Used by:
      - static/js/sos_alerts.js
      - live_events.html
    """
    try:
        org = getattr(current_user, "organization", None)
        if not org:
            return jsonify({"status": "error", "message": "Organization not found"}), 404

        payload = _build_latest_payload(org.id)
        return jsonify(payload), 200

    except Exception as ex:
        # Prevent HTML error pages (which break JS fetch)
        return jsonify({
            "status": "error",
            "message": f"Internal server error: {type(ex).__name__} - {ex}"
        }), 500


# ============================================================
# 🧷 COMPAT ALIASES (to keep older JS / templates working)
# ============================================================

@api_sos.get("/list")
@login_required
def list_alerts():
    """
    Backwards-compatible endpoint for old JS (dashboard.js) that calls /api/sos/list.
    Returns the SAME payload as /api/sos/latest.
    """
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    payload = _build_latest_payload(org.id)
    return jsonify(payload), 200


@api_sos.get("/recent")
@login_required
def recent_alerts():
    """
    Backwards-compatible endpoint for alerts.html which expects /api/sos/recent.
    Returns the SAME payload as /api/sos/latest.
    """
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"status": "error", "message": "Organization not found"}), 404

    payload = _build_latest_payload(org.id)
    return jsonify(payload), 200


@api_sos.post("/trigger")
@login_required
def trigger_manual_alert():
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    data = request.get_json(silent=True) or {}

    alert = Alert(
        organization_id=org.id,
        title=data.get("title", "Manual Alert"),
        message=data.get("message", "Test alert fired manually."),
        severity=data.get("severity", "medium"),
        category=data.get("category", "system"),
    )
    db.session.add(alert)
    db.session.commit()

    # ALSO create an Event so it shows up in the dashboard feed
    from app.models.event import Event
    event = Event(
        organization_id=org.id,
        ts=datetime.now(timezone.utc),
        severity=alert.severity,
        category=alert.category,
        event_type="manual_trigger",
        action="Manual Alert",
        detail=alert.message,
        message=alert.message,
        device_id=None, # No specific device for manual test
        raw={"source": "manual_test"}
    )
    db.session.add(event)
    db.session.commit()

    pref = AlertPreference.query.filter_by(organization_id=org.id).first()
    if pref and pref.email_enabled:
        maybe_send_alert(
            org,
            title=alert.title,
            message=alert.message,
            severity=alert.severity,
            category=alert.category
        )

    return jsonify({"ok": True, "alert_id": alert.id, "event_id": event.id}), 200


# ============================================================
# 🧠 AUTO SOS CREATION (Triggered from Agent Events)
# ============================================================
def auto_sos_from_event(event: Event):
    """
    Automatically create an SOS alert if the event severity is high or critical.
    Used by the agent event ingestion flow.
    """
    if not event or not hasattr(event, "severity"):
        return

    sev = (event.severity or "").lower()
    if sev not in ["high", "critical"]:
        return

    try:
        alert = Alert(
            organization_id=event.organization_id,
            title=f"🚨 {event.category.title()} Alert",
            message=event.detail or "Security event detected.",
            severity=event.severity,
            category=event.category,
        )
        db.session.add(alert)
        db.session.commit()

        org = event.organization
        pref = getattr(org, "alert_preference", None)

        if pref and getattr(pref, "email_enabled", False):
            maybe_send_alert(
                org,
                title=alert.title,
                message=alert.message,
                severity=alert.severity,
                category=alert.category,
            )

    except Exception as ex:
        # Keep it quiet in production logs, but do not crash the app
        print(f"[auto_sos_from_event] Failed to create SOS: {ex}")


# ============================================================
# 🔧 ALERT PREFERENCES (READ)
# ============================================================
@api_sos.get("/prefs")
@login_required
@role_required("admin")
def get_prefs():
    """Fetch current organization's SOS alert preferences."""
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    pref = AlertPreference.query.filter_by(organization_id=org.id).first()
    if not pref:
        # Default settings for new orgs
        return jsonify({
            "email_enabled": True,
            "sms_enabled": False,
            "email_to": "",
            "sms_to": "",
            "min_severity": "high",
            "always_on": False,
            "off_start_hour": 19,
            "off_end_hour": 8,
        }), 200

    return jsonify(pref.to_dict()), 200


# ============================================================
# 🔧 ALERT PREFERENCES (UPDATE)
# ============================================================
@api_sos.post("/prefs")
@login_required
@role_required("admin")
def update_prefs():
    """Save updated alert preferences for the organization admin."""
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"error": "Organization not found"}), 404

    data = request.get_json(silent=True) or {}
    pref = AlertPreference.query.filter_by(organization_id=org.id).first()

    if not pref:
        pref = AlertPreference(organization_id=org.id)
        db.session.add(pref)

    pref.email_enabled = bool(data.get("email_enabled", True))
    pref.sms_enabled = bool(data.get("sms_enabled", False))
    pref.email_to = (data.get("email_to") or "").strip() or None
    pref.sms_to = (data.get("sms_to") or "").strip() or None
    pref.min_severity = (data.get("min_severity") or "high").lower()
    pref.always_on = bool(data.get("always_on", False))
    pref.off_start_hour = int(data.get("off_start_hour", 19))
    pref.off_end_hour = int(data.get("off_end_hour", 8))

    db.session.commit()
    return jsonify({"ok": True, "updated": pref.to_dict()}), 200
