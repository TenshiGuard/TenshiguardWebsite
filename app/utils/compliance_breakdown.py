# app/utils/compliance_breakdown.py

def get_compliance_breakdown(sector: str, plan: str):
    """
    Returns a detailed breakdown of key compliance frameworks and status
    based on sector and subscription plan.
    """
    sector = (sector or "academic").lower()
    plan = (plan or "basic").lower()

    base_data = {
        "academic": {
            "FERPA": True,
            "GDPR": True,
            "ISO 27001": plan != "basic",
            "NIST 800-171": plan == "enterprise",
            "SOC 2": plan == "enterprise"
        },
        "healthcare": {
            "HIPAA": True,
            "GDPR": True,
            "ISO 27001": plan != "basic",
            "SOC 2": plan == "enterprise",
            "NIST 800-53": plan == "enterprise"
        },
        "hospitality": {
            "PCI DSS": True,
            "GDPR": True,
            "ISO 27001": plan != "basic",
            "SOC 2": plan == "enterprise"
        },
        "finance": {
            "PCI DSS": True,
            "SOX": plan != "basic",
            "GDPR": True,
            "ISO 27001": plan != "basic",
            "NIST 800-53": plan == "enterprise"
        },
        "government": {
            "FedRAMP": plan != "basic",
            "FISMA": plan != "basic",
            "ISO 27001": True,
            "NIST 800-53": plan == "enterprise",
            "GDPR": True
        },
    }

    # Fallback if unknown sector
    data = base_data.get(sector, base_data["academic"])
    # Convert to a list of dicts for the template
    breakdown = [{"name": k, "compliant": v} for k, v in data.items()]
    return breakdown
