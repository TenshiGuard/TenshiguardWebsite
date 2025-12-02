# app/ai/correlation/__init__.py

from __future__ import annotations

from typing import List

from .auth_bruteforce import AuthBruteForceRule
from .process_network_link import ProcessNetworkLinkRule
from .file_malware_link import FileMalwareLinkRule
from .telemetry_anomaly import TelemetryAnomalyRule
from .multi_event_timeline import MultiEventTimelineRule
from .lateral_movement import LateralMovementRule
from .ransomware_behavior import RansomwareBehaviorRule


def get_correlation_rules() -> List[object]:
    """
    Factory for all correlation rules.

    Balanced profile (B):
      - reasonable thresholds
      - not too noisy
    """
    return [
        AuthBruteForceRule(),
        ProcessNetworkLinkRule(),
        FileMalwareLinkRule(),
        TelemetryAnomalyRule(),
        MultiEventTimelineRule(),
        LateralMovementRule(),
        RansomwareBehaviorRule(),
    ]
