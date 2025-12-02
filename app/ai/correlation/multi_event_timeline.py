# app/ai/correlation/multi_event_timeline.py

from __future__ import annotations

from typing import Any, Dict, List, Optional
from collections import Counter

from .base_rule import CorrelationRule
from app.models.ai_signal import AISignal


class MultiEventTimelineRule(CorrelationRule):
    name = "MultiEventTimelineRule"
    window_minutes = 30

    def process(
        self,
        org,
        device,
        aisignal: AISignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        org_id = org.id
        device_id = getattr(device, "id", None)

        if not device_id:
            return []

        rule_label = "Escalated Incident Timeline"
        if self._dedup_correlation(org_id, device_id, rule_label, minutes=self.window_minutes):
            return []

        signals = self._recent_signals_for_device(
            device_id=device_id,
            org_id=org_id,
            minutes=self.window_minutes,
        )

        if not signals:
            return []

        # Count high/critical across categories
        high_crit = [s for s in signals if s.severity in ("high", "critical")]
        if len(high_crit) < 4 and len(set(s.category for s in high_crit)) < 3:
            # Balanced profile: require either
            # - at least 4 high/critical signals, OR
            # - at least 3 distinct categories with high/critical
            return []

        cats = Counter([s.category for s in high_crit])
        cat_str = ", ".join(f"{c}({n})" for c, n in cats.items())

        detail = (
            f"Multiple high/critical AI signals were observed for this device in the last "
            f"{self.window_minutes} minutes across categories: {cat_str}. "
            "This indicates an escalated incident (multi-stage attack or lateral movement)."
        )

        mitigation = (
            "Escalate to incident response. Isolate the host, collect forensic data, "
            "review logs across identity, network, and endpoint layers, and consider wider environment impact."
        )

        return [
            self._build_corr_event(
                category="incident",
                severity="critical",
                rule_name=rule_label,
                detail=detail,
                risk_score=95,
                mitigation=mitigation,
            )
        ]
