# app/utils/compliance_score.py

def get_compliance_score(sector: str, plan: str) -> int:
    """
    Returns estimated compliance readiness % based on sector and plan.
    """
    sector = (sector or "academic").lower()
    plan = (plan or "basic").lower()

    # Base compliance score by sector
    base_scores = {
        "academic": 70,
        "healthcare": 75,
        "hospitality": 65,
        "finance": 80,
        "government": 85,
    }

    # Multiplier based on plan
    plan_multipliers = {
        "basic": 1.0,
        "professional": 1.15,
        "enterprise": 1.30,
    }

    base = base_scores.get(sector, 70)
    multiplier = plan_multipliers.get(plan, 1.0)
    score = int(min(base * multiplier, 99))  # Cap at 99%
    return score
