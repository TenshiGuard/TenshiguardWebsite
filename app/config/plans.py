# app/config/plans.py

PLAN_CATALOG = {
    "basic": {
        "name": "Basic",
        "price": 0,
        "devices": 5,
        "features": [
            "Core endpoint monitoring",
            "Basic analytics dashboard",
            "Email alerts"
        ],
        "sos_enabled": False,
    },
    "professional": {
        "name": "Professional",
        "price": 49,
        "devices": "Unlimited",
        "features": [
            "Advanced threat analytics",
            "Unlimited device management",
            "Email + SMS alerts",
            "Priority support",
            "SOS feature access"
        ],
        "sos_enabled": True,
    },
    "enterprise": {
        "name": "Enterprise",
        "price": 99,
        "devices": "Unlimited",
        "features": [
            "24/7 security operations support",
            "Multi-organization dashboard",
            "Incident response automation",
            "SOS escalation workflow",
            "Dedicated security advisor"
        ],
        "sos_enabled": True,
    },
}


def plan_for_id(plan_id: str):
    """Return plan details safely."""
    return PLAN_CATALOG.get(plan_id.lower(), PLAN_CATALOG["basic"])
