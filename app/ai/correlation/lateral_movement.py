from __future__ import annotations

from typing import Any, Dict, List, Optional
from datetime import timedelta

from .base_rule import CorrelationRule
from app.models.event import Event
from app.models.ai_signal import AISignal


class LateralMovementRule(CorrelationRule):
    name = "LateralMovementRule"
    window_minutes = 5

    def process(
        self,
        org,
        device,
        aisignal: AISignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        # Trigger on auth or network signals
        if aisignal.category not in ("auth", "network"):
            return []

        org_id = org.id
        # We need source_ip from the raw event data to track movement
        source_ip = raw.get("source_ip")
        if not source_ip:
            return []

        rule_label = "Lateral Movement Pattern"
        # Note: We dedup by org_id + source_ip conceptually, but our helper uses device_id.
        # We'll stick to device-based dedup for now to avoid noise on the same host.
        if self._dedup_correlation(org_id, getattr(device, "id", None), rule_label, minutes=self.window_minutes):
            return []

        # Find other events from same Source IP across the Organization
        cutoff = self._cutoff(minutes=self.window_minutes)
        
        # We want to see if this IP has touched multiple DEVICES
        recent_events = (
            Event.query
            .filter(Event.organization_id == org_id)
            .filter(Event.source_ip == source_ip)
            .filter(Event.ts >= cutoff)
            .all()
        )

        # Count distinct devices targeted by this IP
        targeted_devices = {e.device_id for e in recent_events if e.device_id}
        
        # If this IP has targeted 2 or more distinct devices
        if len(targeted_devices) < 2:
            return []

        detail = (
            f"Source IP {source_ip} has accessed {len(targeted_devices)} distinct devices "
            f"within the last {self.window_minutes} minutes. "
            "This behavior is indicative of lateral movement."
        )

        mitigation = (
            f"Block IP {source_ip} at the firewall immediately. "
            "Review logs for compromised credentials and inspect accessed devices."
        )

        return [
            self._build_corr_event(
                category="lateral",
                severity="high",
                rule_name=rule_label,
                detail=detail,
                risk_score=85,
                mitigation=mitigation,
            )
        ]
