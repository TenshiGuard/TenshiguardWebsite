# app/ai/services/incident_manager.py

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from flask import current_app

from app.extensions import db
from app.models.incident import Incident
from app.models.event import Event
from app.models.organization import Organization
from app.models.device import Device
from app.models.ai_signal import AISignal


class IncidentManager:
    """
    TenshiGuard Incident Manager

    Responsibilities:
      - Group related AI / correlation outputs into "Incidents"
      - Avoid alert storms by reusing an open incident when possible
      - Maintain severity / risk escalation over time
    """

    def __init__(self, app: Any = None) -> None:
        self.app = app or current_app
        self.logger = getattr(self.app, "logger", None)

    # ------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------
    def _log(self, msg: str) -> None:
        if self.logger:
            self.logger.info("[IncidentManager] %s", msg)

    def _severity_rank(self, sev: str) -> int:
        sev = (sev or "").lower()
        order = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        return order.get(sev, 1)

    def _merge_severity(self, existing: str, new: str) -> str:
        """
        Keep the higher severity when updating an incident.
        """
        if self._severity_rank(new) > self._severity_rank(existing):
            return new
        return existing

    def _normalize_score(self, score: Optional[int]) -> int:
        if score is None:
            return 50
        try:
            s = int(score)
        except Exception:
            return 50
        return max(0, min(s, 100))

    # ------------------------------------------------------------
    # Core: get or create an incident bucket
    # ------------------------------------------------------------
    def _get_or_create_incident(
        self,
        *,
        org: Organization,
        category: str,
        title: str,
        severity: str,
        risk_score: int,
        mitre_tag: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Incident:
        """
        Simple grouping strategy:

        - One open incident per (org, category, title) per rolling 1-hour window.
        - If found, update severity/risk and reuse it.
        - If not found, create a new incident.
        """
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(hours=1)

        q = (
            Incident.query
            .filter(
                Incident.organization_id == org.id,
                Incident.status == "open",
                Incident.category == category,
                Incident.title == title,
                Incident.created_at >= window_start,
            )
            .order_by(Incident.created_at.desc())
        )

        incident = q.first()

        if incident:
            # Escalate severity if new one is higher
            old_sev = incident.severity
            incident.severity = self._merge_severity(incident.severity, severity)

            # Risk: keep the max
            incident.risk_score = max(incident.risk_score or 0, risk_score)

            # Optional: append a short note to description (kept minimal here)
            if description:
                base = incident.description or ""
                # Avoid growing unbounded, keep only a short concatenation
                if len(base) < 2000:
                    if base:
                        base += "\n"
                    base += f"[Update {now.isoformat()}] {description}"
                    incident.description = base

            if mitre_tag and not incident.mitre_tag:
                incident.mitre_tag = mitre_tag

            incident.updated_at = now
            db.session.flush()  # no commit here, caller will commit
            self._log(
                f"Reusing incident #{incident.id} ({old_sev} -> {incident.severity}, score={incident.risk_score})"
            )
            return incident

        # No open incident ⇒ create a new one
        incident = Incident(
            organization_id=org.id,
            title=title,
            description=description or "",
            severity=severity or "medium",
            category=category or "general",
            status="open",
            risk_score=risk_score,
            mitre_tag=mitre_tag or None,
            created_at=now,
            updated_at=now,
        )
        db.session.add(incident)
        db.session.flush()  # ensure incident.id is available

        # 🧠 AI AUTO-ANALYSIS for High/Critical Incidents
        if severity in ("high", "critical"):
            self._trigger_ai_analysis(incident)

        # 🔔 BRIDGE: Create Alert for Dashboard Visibility
        from app.models.alert import Alert
        alert = Alert(
            organization_id=org.id,
            title=f"[AI] {title}",
            message=description or f"New incident detected: {title}",
            severity=severity,
            category=category,
            created_at=now,
            is_read=False
        )
        db.session.add(alert)

        self._log(
            f"Created new incident #{incident.id} and Alert "
            f"[org={org.id}, category={incident.category}, severity={incident.severity}, score={incident.risk_score}]"
        )
        return incident

    def _trigger_ai_analysis(self, incident: Incident) -> None:
        """
        Ask OpenAI to analyze the incident and append insights to description.
        """
        service = getattr(self.app, "openai_service", None)
        if not service:
            return

        try:
            prompt = (
                f"Analyze this security incident:\n"
                f"Title: {incident.title}\n"
                f"Severity: {incident.severity}\n"
                f"Details: {incident.description}\n\n"
                f"Provide a concise analysis and 3 actionable mitigation steps."
            )
            analysis = service.ask_ai(prompt)
            if analysis:
                incident.description = (incident.description or "") + f"\n\n🤖 **AI Analysis**:\n{analysis}"
                db.session.add(incident)
                self._log(f"AI analysis attached to incident #{incident.id}")
        except Exception as e:
            self._log(f"AI analysis failed: {e}")

    # ------------------------------------------------------------
    # Public: register correlation result (recommended path)
    # ------------------------------------------------------------
    def register_from_correlation(
        self,
        *,
        org: Organization,
        device: Optional[Device],
        aisignal: Optional[AISignal],
        corr: Dict[str, Any],
    ) -> Incident:
        """
        Called by correlation engine once per correlation result.

        corr example:
          {
            "category": "auth",
            "severity": "high",
            "rule_name": "Brute force pattern",
            "detail": "...",
            "risk_score": 80,
            "mitigation": "...",
            "mitre_tag": "T1110"
          }
        """
        category = (corr.get("category") or "general").lower()
        severity = corr.get("severity") or (aisignal.severity if aisignal else "medium")
        rule_name = corr.get("rule_name") or (aisignal.rule_name if aisignal else "Correlated activity")
        detail = corr.get("detail") or (aisignal.detail if aisignal else "")
        mitre_tag = corr.get("mitre_tag")
        risk_score = self._normalize_score(
            corr.get("risk_score") or (aisignal.risk_score if aisignal else None)
        )

        title = rule_name

        incident = self._get_or_create_incident(
            org=org,
            category=category,
            title=title,
            severity=severity,
            risk_score=risk_score,
            mitre_tag=mitre_tag,
            description=detail,
        )

        return incident

    # ------------------------------------------------------------
    # Optional: link an Event row directly to an incident
    # (for future use if you want to attach raw Events)
    # ------------------------------------------------------------
    def attach_event_to_incident(
        self,
        *,
        incident: Incident,
        event: Event,
        correlation_score: Optional[int] = None,
    ) -> None:
        """
        Set incident_id + correlation_score on an Event and bump incident updated_at.
        """
        now = datetime.now(timezone.utc)

        event.incident_id = incident.id
        if correlation_score is not None:
            event.correlation_score = self._normalize_score(correlation_score)

        incident.updated_at = now
        db.session.flush()
    # ------------------------------------------------------------
    # Public: register a raw Event as an incident
    # ------------------------------------------------------------
    def register_event(self, event: Event) -> Optional[Incident]:
        """
        Called when a high-severity Event is created directly (e.g. from AI signal).
        """
        if not event.organization_id:
            return None

        # Resolve org
        org = Organization.query.get(event.organization_id)
        if not org:
            return None

        # Map severity
        severity = (event.severity or "medium").lower()
        
        # Map risk score (default to 50 if not present)
        risk_score = 50
        if severity == "high":
            risk_score = 75
        elif severity == "critical":
            risk_score = 90

        # Create/Find incident
        incident = self._get_or_create_incident(
            org=org,
            category=event.category or "general",
            title=event.message or "Security Event",
            severity=severity,
            risk_score=risk_score,
            description=event.detail or event.message,
        )

        # Link event to incident
        self.attach_event_to_incident(incident=incident, event=event)
        
        return incident
