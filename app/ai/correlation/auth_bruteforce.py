# app/ai/correlation/auth_bruteforce.py

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .base_rule import CorrelationRule
from app.models.ai_signal import AISignal


class AuthBruteForceRule(CorrelationRule):
    name = "AuthBruteForceRule"
    window_minutes = 10  # correlation window

    def process(
        self,
        org,
        device,
        aisignal: AISignal,
        raw: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        # Only care about auth-related signals
        if aisignal.category not in ("auth",):
            return []

        org_id = org.id
        device_id = getattr(device, "id", None)

        # Dedup: if we've already created a brute-force correlation recently, skip
        rule_label = "Brute Force Pattern Detected"
        if self._dedup_correlation(org_id, device_id, rule_label, minutes=self.window_minutes):
            return []

        # Count recent auth AI signals for this device
        signals = self._recent_signals_for_device(
            device_id=device_id,
            org_id=org_id,
            minutes=self.window_minutes,
        )

        auth_failures = [s for s in signals if s.category == "auth"]
        if len(auth_failures) < 5:
            # Balanced profile: require at least 5 auth signals within window
            return []

        detail = (
            f"Detected {len(auth_failures)} authentication-related AI signals "
            f"in the last {self.window_minutes} minutes on this endpoint. "
            "Pattern is consistent with a potential brute-force or password spraying attack."
        )

        mitigation = (
            "Enable or tighten lockout policies, enforce MFA, review source IPs, "
            "and block suspicious addresses. Consider adding rate limiting or tools like Fail2Ban."
        )

        return [
            self._build_corr_event(
                category="auth",
                severity="high",
                rule_name=rule_label,
                detail=detail,
                risk_score=80,
                mitigation=mitigation,
            )
        ]
