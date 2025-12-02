# app/routes/api_ai_seed.py
from flask import Blueprint, jsonify, request
from app.extensions import db
from app.models.ai_signal import AISignal
from app.models.organization import Organization
from datetime import datetime, timezone
from app.security.api_key import require_api_key
import random

api_ai_seed = Blueprint("api_ai_seed", __name__, url_prefix="/api/dashboard/ai")


def now():
    return datetime.now(timezone.utc)


@api_ai_seed.route("/seed", methods=["POST"])
@require_api_key   # <-- handles X-API-KEY + X-ORG-ID
def seed_ai_signals(org: Organization):
    """Seed AI test data into AISignal for the given organization."""
    
    sample_rules = [
        ("file", "Suspicious Executable", "high", "Detected unsigned EXE in temp folder"),
        ("file", "Malicious Hash", "critical", "Hash matched ransomware family"),
        ("process", "Encoded PowerShell", "medium", "PowerShell with Base64-encoded command"),
        ("process", "Privilege Escalation", "high", "Process trying to elevate tokens"),
        ("network", "TOR Connection", "critical", "Outbound traffic to TOR exit node"),
        ("network", "Lateral Movement", "high", "SMB probing across internal subnet"),
        ("threat", "Behavioral Anomaly", "medium", "Unusual process-network combination"),
    ]

    signals = []
    for _ in range(25):
        typ, rule, severity, detail = random.choice(sample_rules)
        s = AISignal(
            organization_id=org.id,
            device_id=1,
            type=typ,
            rule_name=rule,
            severity=severity,
            detail=detail,
            risk_score=random.randint(10, 95),
            ts=now(),
        )
        signals.append(s)

    db.session.add_all(signals)
    db.session.commit()

    return jsonify({"ok": True, "inserted": len(signals)})
