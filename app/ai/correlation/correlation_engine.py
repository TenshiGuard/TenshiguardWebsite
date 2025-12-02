# app/ai/services/correlation_engine.py

from __future__ import annotations
from typing import Any, Dict, List, Optional
from flask import current_app
from datetime import datetime, timezone

from app.ai.correlation.correlator import Correlator


class CorrelationEngine:
    """
    Phase 2 – Orchestrator for correlation rules.
    Rules are loaded dynamically from app.ai.correlation.
    The correlator provides memory of last 5 minutes per device.
    """

    def __init__(self, app: Any = None) -> None:
        self.app = app or current_app
        self.logger = getattr(self.app, "logger", None)

        # Memory layer for multi-step correlation
        self.correlator = Correlator()

        # Rule loading
        try:
            from app.ai.correlation import get_correlation_rules
            self.rules = get_correlation_rules()

            if self.logger:
                self.logger.info(
                    "[CorrelationEngine] Initialized with %d rules.",
                    len(self.rules),
                )

            # Attach correlator to all rules
            for r in self.rules:
                r.correlator = self.correlator

        except Exception as e:
            self.rules = []
            if self.logger:
                self.logger.error(
                    "[CorrelationEngine] Failed to load rules: %s",
                    e,
                )

    # --------------------------------------------------------
    # MAIN ENTRYPOINT – called from ingest_ai_event()
    # --------------------------------------------------------
    def process(
        self,
        org,
        device,
        aisignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run all correlation rules and return correlated event objects.
        """
        if not self.rules:
            return []

        org_id = org.id
        dev_id = device.id if device else None

        # Push into memory for future sequences
        self.correlator.push(
            org_id,
            dev_id,
            {
                "type": aisignal.category,
                "severity": aisignal.severity,
                "marker": aisignal.rule_name.lower().replace(" ", "_"),
                "detail": aisignal.detail,
                "ts": aisignal.ts,
            },
        )

        results: List[Dict[str, Any]] = []

        # Run each rule
        for rule in self.rules:
            try:
                result = rule.process(
                    org=org,
                    device=device,
                    aisignal=aisignal,
                    raw=raw or {},
                )

                if not result:
                    continue

                if isinstance(result, dict):
                    results.append(result)
                elif isinstance(result, list):
                    results.extend(result)

            except Exception as e:
                if self.logger:
                    self.logger.error(
                        "[CorrelationEngine] Rule %s failed: %s",
                        getattr(rule, "name", rule.__class__.__name__),
                        e,
                    )

        # Normalize risk_score
        for r in results:
            try:
                rs = int(r.get("risk_score", 50))
                r["risk_score"] = max(0, min(rs, 100))
            except:
                r["risk_score"] = 50

        return results

    # --------------------------------------------------------
    # Called on Event mirror (non-AI events)
    # --------------------------------------------------------
    def process_event(self, event):
        """
        Used for non-AI agent events to still allow chaining.
        """
        org_id = event.organization_id
        dev_id = event.device_id

        marker = (event.event_type or "event").lower()

        self.correlator.push(
            org_id,
            dev_id,
            {
                "type": event.event_type,
                "severity": event.severity,
                "marker": marker,
                "detail": event.detail,
                "ts": event.ts or datetime.now(timezone.utc),
            },
        )
