# app/ai/correlation/process_network_link.py

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base_rule import CorrelationRule
from app.models.ai_signal import AISignal


class ProcessNetworkLinkRule(CorrelationRule):
    name = "ProcessNetworkLinkRule"
    window_minutes = 5

    def process(
        self,
        org,
        device,
        aisignal: AISignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        org_id = org.id
        device_id = getattr(device, "id", None)

        if aisignal.category not in ("process", "network"):
            return []

        rule_label = "Process + Network Correlation"
        if self._dedup_correlation(org_id, device_id, rule_label, minutes=self.window_minutes):
            return []

        # Look for complementary AI signals
        signals = self._recent_signals_for_device(
            device_id=device_id,
            org_id=org_id,
            minutes=self.window_minutes,
        )

        has_proc = any(s.category == "process" and s.severity in ("high", "critical") for s in signals)
        has_net = any(s.category == "network" and s.severity in ("high", "critical") for s in signals)

        if not (has_proc and has_net):
            return []

        detail = (
            "Suspicious process activity and high-risk network connections were both observed "
            f"within the last {self.window_minutes} minutes on this device. "
            "This pattern is consistent with malware establishing command-and-control or data exfiltration."
        )

        mitigation = (
            "Isolate the endpoint from the network, capture a forensic image, "
            "and review process trees and outbound connections. "
            "Block suspicious IPs/domains at the firewall/proxy."
        )

        return [
            self._build_corr_event(
                category="network",
                severity="high",
                rule_name=rule_label,
                detail=detail,
                risk_score=85,
                mitigation=mitigation,
            )
        ]
