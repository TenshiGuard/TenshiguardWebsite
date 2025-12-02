from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base_rule import CorrelationRule
from app.models.event import Event
from app.models.ai_signal import AISignal


class RansomwareBehaviorRule(CorrelationRule):
    name = "RansomwareBehaviorRule"
    window_minutes = 1  # Short window for rapid activity

    def process(
        self,
        org,
        device,
        aisignal: AISignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        # Trigger on file signals
        if aisignal.category != "file":
            return []

        org_id = org.id
        device_id = getattr(device, "id", None)
        if not device_id:
            return []

        rule_label = "Ransomware Behavior Pattern"
        if self._dedup_correlation(org_id, device_id, rule_label, minutes=5): # Dedup for 5 mins
            return []

        # 1. Check for suspicious extensions in the current signal
        detail_text = aisignal.detail or ""
        suspicious_exts = [".enc", ".locked", ".crypt", ".wannacry"]
        if any(ext in detail_text for ext in suspicious_exts):
             return [
                self._build_corr_event(
                    category="ransomware",
                    severity="critical",
                    rule_name=rule_label,
                    detail=f"Encrypted file extension detected: {detail_text}",
                    risk_score=98,
                    mitigation="Quarantine device IMMEDIATELY. Stop processes. Disable network.",
                )
            ]

        # 2. Detect rapid file modifications (Mass encryption/deletion)
        # We look at raw EVENTS, not just signals, to catch the volume
        cutoff = self._cutoff(minutes=self.window_minutes)
        
        file_event_count = (
            Event.query
            .filter(Event.organization_id == org_id)
            .filter(Event.device_id == device_id)
            .filter(Event.category == "file")
            .filter(Event.ts >= cutoff)
            .count()
        )

        if file_event_count >= 20:
             return [
                self._build_corr_event(
                    category="ransomware",
                    severity="critical",
                    rule_name=rule_label,
                    detail=f"Rapid file modification detected ({file_event_count} events in 1 min). Possible mass encryption.",
                    risk_score=95,
                    mitigation="Quarantine device IMMEDIATELY. Stop processes. Disable network.",
                )
            ]

        return []
