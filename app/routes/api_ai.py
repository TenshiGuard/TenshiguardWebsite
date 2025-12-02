# app/routes/api_ai.py

from flask import Blueprint, jsonify
from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models.ai_signal import AISignal
from app.security.api_key import require_api_key
from flask_login import login_required

api_ai_bp = Blueprint("api_ai_bp", __name__, url_prefix="/api/dashboard/ai")


def now_utc():
    return datetime.now(timezone.utc)


# 1. Latest AI signals
@api_ai_bp.get("/latest")
@require_api_key
def api_ai_latest(org):
    items = (
        AISignal.query.filter_by(organization_id=org.id)
        .order_by(AISignal.ts.desc())
        .limit(50)
        .all()
    )

    out = []
    for s in items:
        dev_name = s.device.device_name if s.device else "Unknown Device"
        out.append(
            {
                "ts": s.ts.strftime("%Y-%m-%d %H:%M:%S"),
                "category": s.category,
                "severity": s.severity,
                "rule_name": s.rule_name,
                "detail": s.detail,
                "risk_score": s.risk_score,
                "device_name": dev_name,
            }
        )

    return jsonify({"ok": True, "items": out}), 200


# 2. Summary metrics
@api_ai_bp.get("/summary")
@require_api_key
def api_ai_summary(org):
    total = AISignal.query.filter_by(organization_id=org.id).count()

    since = now_utc() - timedelta(hours=24)
    high24 = (
        AISignal.query.filter_by(organization_id=org.id)
        .filter(AISignal.ts >= since)
        .filter(AISignal.severity.in_(["high", "critical"]))
        .count()
    )

    scores = [
        r[0]
        for r in db.session.query(AISignal.risk_score)
        .filter_by(organization_id=org.id)
        .all()
        if r[0] is not None
    ]

    max_risk = max(scores) if scores else 0
    avg_risk = round(sum(scores) / len(scores), 2) if scores else 0

    return (
        jsonify(
            {
                "ok": True,
                "data": {
                    "total": total,
                    "high24": high24,
                    "max_risk": max_risk,
                    "avg_risk": avg_risk,
                },
            }
        ),
        200,
    )


# 3. Category listing
@api_ai_bp.get("/list/<string:category>")
@require_api_key
def api_ai_list_category(org, category):
    valid = ["file", "process", "network", "behavior"]
    if category not in valid:
        return jsonify({"ok": False, "message": "Invalid category"}), 400

    items = (
        AISignal.query.filter_by(organization_id=org.id, category=category)
        .order_by(AISignal.ts.desc())
        .limit(200)
        .all()
    )

    out = []
    for s in items:
        out.append(
            {
                "ts": s.ts.strftime("%Y-%m-%d %H:%M:%S"),
                "severity": s.severity,
                "rule": s.rule_name,
                "detail": s.detail,
                "risk_score": s.risk_score,
            }
        )

    return jsonify({"ok": True, "items": out}), 200


# 4. Seed (demo only)
@api_ai_bp.post("/seed")
@require_api_key
def api_ai_seed(org):
    sample = [
        (
            "file",
            "high",
            "Known Malware Hash",
            "Detected malware: mimikatz.exe",
            88,
        ),
        (
            "process",
            "medium",
            "Suspicious PowerShell",
            "Encoded PowerShell command",
            52,
        ),
        (
            "network",
            "critical",
            "C2 Traffic",
            "Outbound to 185.193.88.23:4444",
            93,
        ),
        (
            "behavior",
            "high",
            "Privilege Escalation Pattern",
            "Token impersonation attempt",
            81,
        ),
    ]

    now = now_utc()
    for category, sev, rule, detail, score in sample:
        row = AISignal(
            organization_id=org.id,
            device_id=None,
            category=category,
            severity=sev,
            rule_name=rule,
            detail=detail,
            risk_score=score,
            ts=now,
        )
        db.session.add(row)

    db.session.commit()
    return jsonify({"ok": True, "message": "Seed data inserted"}), 200


# 5. Ask AI (OpenAI Integration)
@api_ai_bp.post("/ask")
# @login_required
def api_ai_ask():
    from flask import request, current_app
    
    data = request.get_json() or {}
    prompt = data.get("prompt")
    context = data.get("context")
    
    if not prompt:
        return jsonify({"ok": False, "message": "Missing prompt"}), 400
        
    service = getattr(current_app, "gemini_service", None)
    if not service:
        return jsonify({"ok": False, "message": "AI Service not available"}), 503
        
    response = service.ask_ai(prompt, context)
    return jsonify({"ok": True, "response": response}), 200
