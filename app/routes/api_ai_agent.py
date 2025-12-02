"""
TenshiGuard – Unified AI Event Ingest Endpoint
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, current_app
import json

from app.extensions import db
from app.models.organization import Organization
from app.models.device import Device
from app.models.ai_signal import AISignal
from app.models.event import Event
from app.ai.services.incident_manager import IncidentManager

api_ai_agent_bp = Blueprint("api_ai_agent_bp", __name__, url_prefix="/api/agent/ai")


# ------------------------------------------------------------
# Helper: Resolve organization by org_token
# ------------------------------------------------------------
def _get_org_from_token():
    data = request.json or {}
    org_token = data.get("org_token")

    if not org_token:
        return None, jsonify({"ok": False, "message": "Missing org_token"}), 400

    org = Organization.query.filter_by(agent_token=org_token).first()
    if not org:
        return None, jsonify({"ok": False, "message": "Invalid org_token"}), 404

    return org, None, None


# ------------------------------------------------------------
# Helper: Device Upsert by MAC
# ------------------------------------------------------------
def _get_or_create_device(org: Organization, data: dict) -> tuple[Device | None, str | None]:
    mac = data.get("mac")
    hostname = data.get("hostname") or "unknown"
    os_name = data.get("os") or "unknown"
    ip = data.get("ip") or "unknown"

    if not mac:
        return None, None

    dev = Device.query.filter_by(organization_id=org.id, mac=mac).first()
    if dev:
        dev.device_name = hostname
        dev.os = os_name
        dev.ip = ip
        dev.status = "online"
        return dev, None

    # Check Subscription Limit
    count = Device.query.filter_by(organization_id=org.id).count()
    sub = getattr(org, "subscription", None)
    plan = (sub.plan if sub and sub.plan else "basic").lower()

    if plan == "basic" and count >= 5:
        return None, "Basic plan limit reached (max 5 agents). Please upgrade."

    dev = Device(
        organization_id=org.id,
        device_name=hostname,
        mac=mac,
        os=os_name,
        ip=ip,
        status="online",
    )
    db.session.add(dev)
    return dev, None


# ------------------------------------------------------------
# MAIN INGEST ENDPOINT
# ------------------------------------------------------------
@api_ai_agent_bp.post("/event")
def ingest_ai_event():
    data = request.json or {}

    # 1) Resolve organization
    org, err_body, err_code = _get_org_from_token()
    if org is None:
        return err_body, err_code

    # 2) Resolve or create device
    device, error_msg = _get_or_create_device(org, data)
    if error_msg:
        return jsonify({"ok": False, "message": error_msg}), 403

    # 3) Normalize payload (common envelope)
    event_type = (data.get("type") or data.get("category") or "").lower().strip()

    normalized = {
        "type": event_type,
        "hostname": data.get("hostname"),
        "mac": data.get("mac"),
        "ip": data.get("ip"),
        # Process
        "process_name": data.get("process_name"),
        "cmdline": data.get("cmdline"),
        # File
        "file_name": data.get("file_name"),
        "file_hash": data.get("file_hash"),
        "path": data.get("path"),
        # Network
        "dest_ip": data.get("dest_ip"),
        "dest_port": data.get("dest_port"),
        "domain": data.get("domain"),
        "protocol": data.get("protocol"),
        # Auth
        "action": data.get("action"),
        "username": data.get("username"),
        "source_ip": data.get("source_ip"),
        "raw_line": data.get("raw_line"),
        # Behavior
        "behavior_type": data.get("behavior_type"),
        "description": data.get("description"),
        "detail": data.get("detail"),
    }

    # 4) AI Engine
    engine = getattr(current_app, "ai_engine", None)
    if engine is None:
        return jsonify({"ok": False, "message": "AI engine not configured"}), 500

    ai_signal = engine.analyze(normalized)

    # Create an IncidentManager instance (used later)
    incident_mgr = IncidentManager(current_app)

    # ------------------------------------------------------------
    # 5) NO AI MATCH → still store a baseline Event & run correlation
    # ------------------------------------------------------------
    # ------------------------------------------------------------
    # 5) NO AI MATCH → still store a baseline Event & run correlation
    # ------------------------------------------------------------
    if not ai_signal:
        msg = f"Agent event ({event_type or 'unknown'}) received with no AI rule match."

        live = Event(
            organization_id=org.id,
            device_id=device.id if device else None,
            event_type=event_type or "agent",
            category=event_type or "general",
            severity="info",
            action=normalized.get("action") or "",
            mac=normalized.get("mac"),
            source_ip=normalized.get("source_ip"),
            detail=msg,
            message=msg,
            mitigation="No immediate action required. Monitor for anomalies.",
            ts=datetime.now(timezone.utc),
        )
        db.session.add(live)
        db.session.commit()

        # Correlation engine may still want to see every event
        try:
            corr = getattr(current_app, "correlation_engine", None)
            if corr:
                # NOTE: current CorrelationEngine works on AISignals, so here
                # we just pass-through; future extension could wrap Events too.
                current_app.logger.debug("[corr] no-match event ingested (id=%s)", live.id)
        except Exception as e:
            current_app.logger.error(f"[corr] engine error: {e}")

        return jsonify({"ok": True, "ai_match": False}), 200

    # ------------------------------------------------------------
    # 6) Save AI Signal
    # ------------------------------------------------------------
    signal_row = AISignal(
        organization_id=org.id,
        device_id=device.id if device else None,
        mac=normalized.get("mac"),
        category=ai_signal["category"],
        severity=ai_signal["severity"],
        rule_name=ai_signal.get("rule_hits", [])[0] if ai_signal.get("rule_hits") else "ai_rule",
        detail=ai_signal.get("detail") or json.dumps(ai_signal.get("behaviour", {})),
        risk_score=ai_signal.get("risk_score", 50),
        mitigation=ai_signal.get("mitigation", ""),
        raw=ai_signal.get("raw", normalized),
    )
    db.session.add(signal_row)
    db.session.flush()  # get signal_row.id without full commit

    # ------------------------------------------------------------
    # 7) Run Correlation Engine on this AISignal
    # ------------------------------------------------------------
    corr_engine = getattr(current_app, "correlation_engine", None)
    correlated_events = []

    if corr_engine:
        try:
            correlated_events = corr_engine.process(
                org=org,
                device=device,
                aisignal=signal_row,
                raw=data,
            )
            current_app.logger.info(
                "[correlation] %d correlated event(s) generated for signal %s.",
                len(correlated_events),
                signal_row.id,
            )
        except Exception as e:
            current_app.logger.error(f"[correlation] engine failed: {e}")

    # ------------------------------------------------------------
    # 8) Persist Correlated Events + register Incidents
    # ------------------------------------------------------------
    for ce in correlated_events:
        corr_score = int(ce.get("risk_score", 0)) if ce.get("risk_score") is not None else 0

        live_corr = Event(
            organization_id=org.id,
            device_id=device.id if device else None,
            event_type="correlation",
            category=ce.get("category") or "correlation",
            severity=ce.get("severity") or ai_signal.get("severity", "medium"),
            action="correlation",
            mac=normalized.get("mac"),
            detail=ce.get("detail", ""),
            message=f"[Correlation] {ce.get('rule_name', 'correlation')} — {ce.get('detail', '')}",
            mitigation=ce.get("mitigation") or "Investigate correlated anomaly patterns.",
            ts=datetime.now(timezone.utc),
            correlation_score=corr_score,
            correlation_key=ce.get("correlation_key"),
        )
        db.session.add(live_corr)
        db.session.flush()  # ensure live_corr.id is available

        # 🔗 Register / update Incident for this correlated event
        try:
            incident = incident_mgr.register_event(live_corr)
            if incident:
                live_corr.incident_id = incident.id
        except Exception as e:
            current_app.logger.error(f"[incident] register_event failed for event {live_corr.id}: {e}")

    # ------------------------------------------------------------
    # 9) Mirror original AI signal into Event table
    # ------------------------------------------------------------
    live_message = f"{ai_signal.get('rule_hits', ['ai_rule'])[0] if ai_signal.get('rule_hits') else 'AI Detection'} — {ai_signal.get('severity', 'info')}"
    
    live = Event(
        organization_id=org.id,
        device_id=device.id if device else None,
        event_type=ai_signal["category"],
        category=ai_signal["category"],
        severity=ai_signal["severity"],
        action=normalized.get("action") or "",
        mac=normalized.get("mac"),
        source_ip=normalized.get("source_ip"),
        detail=ai_signal.get("detail") or json.dumps(ai_signal.get("behaviour", {})),
        message=live_message,
        mitigation=ai_signal.get("mitigation", ""),
        ts=datetime.now(timezone.utc),
    )
    db.session.add(live)
    db.session.flush()

    # Optionally: treat high/critical AI signals as incidents even without correlation
    try:
        if (ai_signal.get("severity") or "").lower() in ("high", "critical"):
            incident = incident_mgr.register_event(live)
            if incident:
                live.incident_id = incident.id
    except Exception as e:
        current_app.logger.error(f"[incident] register_event failed for AI event {live.id}: {e}")

    # Final commit for signal + events + incidents
    db.session.commit()

    return jsonify({
        "ok": True,
        "signal_saved": True,
        "ai_match": True,
        "id": signal_row.id,
        "category": signal_row.category,
        "severity": signal_row.severity,
        "rule_name": signal_row.rule_name,
        "risk_score": signal_row.risk_score,
    }), 201
