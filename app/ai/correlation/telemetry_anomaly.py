# app/ai/correlation/telemetry_anomaly.py

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base_rule import CorrelationRule
from app.models.device_telemetry import DeviceTelemetry
from app.models.ai_signal import AISignal


class TelemetryAnomalyRule(CorrelationRule):
    name = "TelemetryAnomalyRule"
    window_minutes = 10

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

        # Trigger only for high/critical AI signals
        if aisignal.severity not in ("high", "critical"):
            return []

        rule_label = "High Resource Usage on Compromised Host"
        if self._dedup_correlation(org_id, device_id, rule_label, minutes=self.window_minutes):
            return []

        # Get last telemetry for this device
        tel = (
            DeviceTelemetry.query.filter_by(device_id=device_id)
            .order_by(DeviceTelemetry.ts.desc())
            .first()
        )
        if not tel:
            return []

        cpu = tel.cpu_percent or 0
        mem = tel.mem_percent or 0

        # Balanced thresholds
        if cpu <= 85 and mem <= 90:
            return []

        detail = (
            f"Recent AI signal (severity={aisignal.severity}) combined with high resource usage "
            f"(CPU={cpu:.1f}%, MEM={mem:.1f}%) on this endpoint. "
            "This is consistent with crypto miners, intense malware activity, or data exfiltration tooling."
        )

        mitigation = (
            "Investigate running processes, check for crypto miners or unwanted workloads, "
            "and consider isolating the host while analysis is performed."
        )

        return [
            self._build_corr_event(
                category="telemetry",
                severity="high",
                rule_name=rule_label,
                detail=detail,
                risk_score=78,
                mitigation=mitigation,
            )
        ]
