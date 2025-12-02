# app/routes/alerts.py
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from app.models.alert import Alert, AlertPreference
from app.extensions import db
from app.security.permissions import role_required

alerts_bp = Blueprint("alerts_bp", __name__, url_prefix="/api/alerts")

# ============================================================
# 🔹 Get Alerts
# ============================================================
@alerts_bp.get("/")
@login_required
def list_alerts():
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"items": []})
    items = (
        Alert.query.filter_by(organization_id=org.id)
        .order_by(Alert.created_at.desc())
        .limit(20)
        .all()
    )
    return jsonify({"items": [a.to_dict() for a in items]})


# ============================================================
# 🔹 Create / Trigger Alert (manual test)
# ============================================================
@alerts_bp.post("/trigger")
@login_required
@role_required("admin")
def trigger_alert():
    org = getattr(current_user, "organization", None)
    if not org:
        return jsonify({"ok": False, "error": "No organization found"}), 400

    data = request.get_json(silent=True) or {}
    alert = Alert(
        organization_id=org.id,
        title=data.get("title", "Manual Alert"),
        message=data.get("message", "Security alert triggered."),
        severity=data.get("severity", "high"),
        category=data.get("category", "security")
    )
    db.session.add(alert)
    db.session.commit()

    return jsonify({"ok": True, "alert": alert.to_dict()})
