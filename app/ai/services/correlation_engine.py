# app/ai/services/correlation_engine.py

from __future__ import annotations

from typing import Any, Dict, List, Optional

from flask import current_app

from app.ai.services.incident_manager import IncidentManager


class CorrelationEngine:
    """
    Phase 2 – Correlation Engine

    Orchestrates multiple correlation rules:
      - auth_bruteforce
      - process_network_link
      - file_malware_link
      - telemetry_anomaly
      - multi_event_timeline

    Each rule returns 0..N correlation events, which are then:
      - Normalized
      - Linked to an Incident via IncidentManager
      - Returned to the ingest pipeline, which persists them as Event rows.
    """

    def __init__(self, app: Any = None) -> None:
        self.app = app or current_app
        self.logger = getattr(self.app, "logger", None)

        # Load rule instances from app.ai.correlation
        try:
            from app.ai.correlation import get_correlation_rules

            self.rules = get_correlation_rules()
            if self.logger:
                self.logger.info(
                    "[CorrelationEngine] initialized with %d rule(s).",
                    len(self.rules),
                )
        except Exception as e:
            self.rules = []
            if self.logger:
                self.logger.error("[CorrelationEngine] failed to load rules: %s", e)

        # Attach IncidentManager
        try:
            self.incidents = IncidentManager(app=self.app)
            if self.logger:
                self.logger.info("[CorrelationEngine] IncidentManager attached.")
        except Exception as e:
            self.incidents = None
            if self.logger:
                self.logger.error("[CorrelationEngine] IncidentManager init failed: %s", e)

    # ------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------
    def process(
        self,
        org,
        device,
        aisignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run all registered correlation rules against a new AISignal.

        Returns a list of correlation event dicts:

            {
              "category": "auth",
              "severity": "high",
              "rule_name": "Brute force pattern",
              "detail": "...",
              "risk_score": 80,
              "mitigation": "lock account ...",
              "incident_id": 123
            }
        """
        if not self.rules:
            return []

        if self.logger:
            self.logger.debug(
                "[CorrelationEngine] processing aisignal #%s (org=%s)",
                getattr(aisignal, "id", None),
                getattr(org, "id", None),
            )

        results: List[Dict[str, Any]] = []

        # 1) Run all correlation rules
        for rule in self.rules:
            try:
                out = rule.process(
                    org=org,
                    device=device,
                    aisignal=aisignal,
                    raw=raw or {},
                )
                if not out:
                    continue

                if isinstance(out, dict):
                    results.append(out)
                elif isinstance(out, list):
                    results.extend(out)
            except Exception as e:
                if self.logger:
                    self.logger.error(
                        "[CorrelationEngine] rule %s failed: %s",
                        getattr(rule, "name", rule.__class__.__name__),
                        e,
                    )

        if not results:
            return []

        # 2) Normalize risk_score and link to incidents
        enriched: List[Dict[str, Any]] = []

        for r in results:
            # Normalize risk score
            try:
                rs = int(r.get("risk_score", 50))
            except Exception:
                rs = 50
            rs = max(0, min(rs, 100))
            r["risk_score"] = rs

            # Attach incident_id via IncidentManager
            if self.incidents and org is not None:
                try:
                    incident = self.incidents.register_from_correlation(
                        org=org,
                        device=device,
                        aisignal=aisignal,
                        corr=r,
                    )
                    if incident:
                        r["incident_id"] = incident.id
                except Exception as e:
                    if self.logger:
                        self.logger.error(
                            "[CorrelationEngine] incident linking failed: %s", e
                        )

            enriched.append(r)

        return enriched
