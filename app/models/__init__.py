# app/models/__init__.py
# ============================================================
#  TenshiGuard — Unified Model Registry (Final Stable Version)
# ============================================================

from app.extensions import db

# ------------------------------------------------------------
# Core Models
# ------------------------------------------------------------
from .user import User
from .organization import Organization
from .subscription import Subscription
from .device import Device
from .device_telemetry import DeviceTelemetry   # FIXED: correct import
from .event import Event

# ------------------------------------------------------------
# Alerts
# ------------------------------------------------------------
from .alert import Alert, AlertPreference   # both come from alert.py only

# ------------------------------------------------------------
# AI Models
# ------------------------------------------------------------
from .ai_file import AIFileScan
from .ai_process import AIProcessEvent
from .ai_network import AINetworkEvent
from .ai_event import AIEvent
from .ai_behavior_event import AIBehaviorEvent
from .ai_risk_score import AIRiskScore
from .ai_signal import AISignal
from .ai_learned_rule import AILearnedRule


# ------------------------------------------------------------
# Export List
# ------------------------------------------------------------
__all__ = [
    # Core
    "User",
    "Organization",
    "Subscription",
    "Device",
    "DeviceTelemetry",
    "Event",

    # Alerts
    "Alert",
    "AlertPreference",

    # AI
    "AIFileScan",
    "AIProcessEvent",
    "AINetworkEvent",
    "AIEvent",
    "AIBehaviorEvent",
    "AIRiskScore",
    "AISignal",
    "AILearnedRule",
]
