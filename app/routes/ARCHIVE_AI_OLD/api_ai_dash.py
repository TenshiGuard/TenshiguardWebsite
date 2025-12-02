# ============================================================
# 🧠 TenshiGuard — AI Dashboard API (Phase 2)
# ============================================================

from flask import Blueprint, jsonify
from flask_login import login_required
from sqlalchemy import desc, func

from app.extensions import db
from app.models import (
    AIFileScan,
    AIProcessEvent,
    AINetworkEvent,
    AIBehaviorEvent,
    AIRiskScore,
    Device,
)

api_ai_dash = Blueprint("api_ai_dash", __name__, url_prefix="/api/dashboard/ai")


# ============================================================
# 1) LATEST AI FINDINGS (last 20 insights)
# ============================================================

@api_ai_dash.get("/latest")
@login_required
def ai_latest():
    results = []

    files = AIFileScan.query.order_by(desc(AIFileScan.created_at)).limit(10).all()
    procs = AIProcessEvent.query.order_by(desc(AIProcessEvent.created_at)).limit(10).all()
    nets = AINetworkEvent.query.order_by(desc(AINetworkEvent.created_at)).limit(10).all()
    beh = AIBehaviorEvent.query.order_by(desc(AIBehaviorEvent.created_at)).limit(10).all()

    for item in files + procs + nets + beh:
        results.append(item.to_dict())

    # Sort again by timestamp for mixed output
    results = sorted(results, key=lambda x: x["created_at"], reverse=True)

    return jsonify({"ok": True, "latest": results[:20]}), 200


# ============================================================
# 2) DEVICE AI PROFILE
# ============================================================

@api_ai_dash.get("/device/<int:device_id>")
@login_required
def ai_device(device_id):
    data = {
        "files": [x.to_dict() for x in AIFileScan.query.filter_by(device_id=device_id).order_by(desc(AIFileScan.created_at)).all()],
        "processes": [x.to_dict() for x in AIProcessEvent.query.filter_by(device_id=device_id).order_by(desc(AIProcessEvent.created_at)).all()],
        "network": [x.to_dict() for x in AINetworkEvent.query.filter_by(device_id=device_id).order_by(desc(AINetworkEvent.created_at)).all()],
        "behaviors": [x.to_dict() for x in AIBehaviorEvent.query.filter_by(device_id=device_id).order_by(desc(AIBehaviorEvent.created_at)).all()],
        "risk_scores": [x.to_dict() for x in AIRiskScore.query.filter_by(device_id=device_id).order_by(desc(AIRiskScore.created_at)).all()],
    }

    return jsonify({"ok": True, "device_id": device_id, "data": data}), 200


# ============================================================
# 3) GLOBAL AI SUMMARY (for dashboard charts)
# ============================================================

@api_ai_dash.get("/summary")
@login_required
def ai_summary():
    # Top malicious hashes
    top_files = (
        db.session.query(AIFileScan.file_hash, func.count(AIFileScan.id).label("count"))
        .group_by(AIFileScan.file_hash)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )

    # Most suspicious processes
    top_procs = (
        db.session.query(AIProcessEvent.process_name, func.count(AIProcessEvent.id).label("count"))
        .group_by(AIProcessEvent.process_name)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )

    # High risk devices
    high_risk = (
        AIRiskScore.query.filter(AIRiskScore.score >= 60)
        .order_by(desc(AIRiskScore.score))
        .limit(5)
        .all()
    )

    # Severity distribution
    severity_counts = {
        "file": _severity_count(AIFileScan),
        "process": _severity_count(AIProcessEvent),
        "network": _severity_count(AINetworkEvent),
        "behavior": _severity_count(AIBehaviorEvent),
    }

    return jsonify({
        "ok": True,
        "top_files": [{"hash": h, "count": c} for h, c in top_files],
        "top_processes": [{"name": p, "count": c} for p, c in top_procs],
        "high_risk_devices": [x.to_dict() for x in high_risk],
        "severity_distribution": severity_counts,
    }), 200


# ============================================================
# Helper
# ============================================================

def _severity_count(model):
    rows = db.session.query(model.severity, func.count(model.id)).group_by(model.severity).all()
    return {sev or "unknown": count for sev, count in rows}
