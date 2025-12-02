# app/routes/api_ai_dashboard.py
# ============================================================
# 📊 TenshiGuard AI Dashboard API
#    - Backend only (protected by API key)
#    - Used by React/JS charts, not by browser directly
# ============================================================

from datetime import datetime
from typing import List, Dict, Any

from flask import Blueprint, jsonify
from app.extensions import db

from app.models import (
    Device,
    AIFileScan,
    AIProcessEvent,
    AINetworkEvent,
    AIEvent,
    AIRiskScore,
)

from app.utils.api_auth import require_api_key

api_ai_dash = Blueprint("api_ai_dash", __name__, url_prefix="/api/dashboard/ai")


# ------------------------------------------------------------
# Helper: serialize timestamps safely
# ------------------------------------------------------------
def _iso(dt: datetime | None) -> str | None:
    if not dt:
        return None
    return dt.isoformat()


# ------------------------------------------------------------
# Helper: build unified event objects
# ------------------------------------------------------------
def _serialize_file(row: AIFileScan) -> Dict[str, Any]:
    return {
        "type": "file",
        "id": row.id,
        "device_id": row.device_id,
        "organization_id": row.organization_id,
        "severity": row.severity,
        "score": row.score,
        "rule_id": row.rule_id,
        "rule_name": row.rule_name,
        "file_hash": row.file_hash,
        "file_path": row.file_path,
        "findings": row.findings_json or {},
        "created_at": _iso(row.created_at),
    }


def _serialize_process(row: AIProcessEvent) -> Dict[str, Any]:
    return {
        "type": "process",
        "id": row.id,
        "device_id": row.device_id,
        "organization_id": row.organization_id,
        "severity": row.severity,
        "score": row.score,
        "rule_id": row.rule_id,
        "process_name": row.process_name,
        "command_line": row.command_line,
        "findings": row.findings_json or {},
        "created_at": _iso(row.created_at),
    }


def _serialize_network(row: AINetworkEvent) -> Dict[str, Any]:
    return {
        "type": "network",
        "id": row.id,
        "device_id": row.device_id,
        "organization_id": row.organization_id,
        "severity": row.severity,
        "score": row.score,
        "rule_id": row.rule_id,
        "dest_ip": row.dest_ip,
        "dest_port": row.dest_port,
        "findings": row.findings_json or {},
        "created_at": _iso(row.created_at),
    }


def _serialize_behavior(row: AIEvent) -> Dict[str, Any]:
    return {
        "type": "behavior",
        "id": row.id,
        "device_id": row.device_id,
        "organization_id": row.organization_id,
        "event_type": row.event_type,
        "severity": row.severity,
        "score": row.score,
        "findings": row.findings_json or {},
        "raw": row.raw_json or {},
        "created_at": _iso(row.created_at),
    }


# ============================================================
# 1) Latest AI events across the tenant
# ============================================================
@api_ai_dash.get("/latest")
@require_api_key
def ai_latest():
    """
    Return latest AI findings across all devices (for a scrolling timeline).
    """

    # You can tune these limits as needed
    limit_per_type = 20

    files = (
        AIFileScan.query.order_by(AIFileScan.created_at.desc())
        .limit(limit_per_type)
        .all()
    )
    procs = (
        AIProcessEvent.query.order_by(AIProcessEvent.created_at.desc())
        .limit(limit_per_type)
        .all()
    )
    nets = (
        AINetworkEvent.query.order_by(AINetworkEvent.created_at.desc())
        .limit(limit_per_type)
        .all()
    )
    behaviors = (
        AIEvent.query.order_by(AIEvent.created_at.desc())
        .limit(limit_per_type)
        .all()
    )

    items: List[Dict[str, Any]] = []
    items.extend(_serialize_file(r) for r in files)
    items.extend(_serialize_process(r) for r in procs)
    items.extend(_serialize_network(r) for r in nets)
    items.extend(_serialize_behavior(r) for r in behaviors)

    # Sort in Python by created_at descending
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    return jsonify(
        {
            "ok": True,
            "total": len(items),
            "items": items[:80],  # global cap
        }
    ), 200


# ============================================================
# 2) AI detail for one device
# ============================================================
@api_ai_dash.get("/device/<int:device_id>")
@require_api_key
def ai_device(device_id: int):
    """
    Return AI activity focused on a single device.
    Useful for clicking into a device from the dashboard.
    """

    device = Device.query.get(device_id)
    if not device:
        return jsonify({"ok": False, "error": "Device not found"}), 404

    files = (
        AIFileScan.query.filter_by(device_id=device_id)
        .order_by(AIFileScan.created_at.desc())
        .limit(50)
        .all()
    )
    procs = (
        AIProcessEvent.query.filter_by(device_id=device_id)
        .order_by(AIProcessEvent.created_at.desc())
        .limit(50)
        .all()
    )
    nets = (
        AINetworkEvent.query.filter_by(device_id=device_id)
        .order_by(AINetworkEvent.created_at.desc())
        .limit(50)
        .all()
    )
    behaviors = (
        AIEvent.query.filter_by(device_id=device_id)
        .order_by(AIEvent.created_at.desc())
        .limit(50)
        .all()
    )

    return jsonify(
        {
            "ok": True,
            "device": {
                "id": device.id,
                "name": device.device_name,
                "status": device.status,
                "last_seen": _iso(device.last_seen),
            },
            "files": [_serialize_file(r) for r in files],
            "processes": [_serialize_process(r) for r in procs],
            "network": [_serialize_network(r) for r in nets],
            "behaviors": [_serialize_behavior(r) for r in behaviors],
        }
    ), 200


# ============================================================
# 3) Tenant-wide AI summary
# ============================================================
@api_ai_dash.get("/summary")
@require_api_key
def ai_summary():
    """
    Lightweight summary:
      - total AI events per type
      - simple risk score per device (if AIRiskScore populated)
    """

    total_files = AIFileScan.query.count()
    total_procs = AIProcessEvent.query.count()
    total_nets = AINetworkEvent.query.count()
    total_behaviors = AIEvent.query.count()

    # Top-risk devices (if AIRiskScore used)
    risk_rows = (
        AIRiskScore.query.order_by(AIRiskScore.score.desc())
        .limit(10)
        .all()
    )

    top_devices = []
    for r in risk_rows:
        dev = Device.query.get(r.device_id)
        if not dev:
            continue
        top_devices.append(
            {
                "device_id": dev.id,
                "device_name": dev.device_name,
                "score": r.score,
                "highest_severity": r.highest_severity,
                "last_seen": _iso(dev.last_seen),
            }
        )

    return jsonify(
        {
            "ok": True,
            "totals": {
                "file_scans": total_files,
                "process_events": total_procs,
                "network_events": total_nets,
                "behavior_events": total_behaviors,
            },
            "top_risk_devices": top_devices,
        }
    ), 200
