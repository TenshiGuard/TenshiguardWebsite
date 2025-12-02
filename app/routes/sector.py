from flask import Blueprint, render_template
from flask_login import login_required, current_user
from app.models.organization import Organization

sector = Blueprint("sector", __name__, url_prefix="/sector")


def _get_context():
    """Safely fetch user and organization info for current user."""
    org = getattr(current_user, "organization", None)

    # Fallback: query if not attached to user
    if not org and getattr(current_user, "organization_id", None):
        org = Organization.query.get(current_user.organization_id)

    total_users = 0
    total_devices = 0
    if org:
        total_users = getattr(org, "total_users", 0) or 0
        total_devices = getattr(org, "total_devices", 0) or 0

    # ✅ include current_user in context
    return {
        "user": current_user,
        "org": org,
        "total_users": total_users,
        "total_devices": total_devices,
    }


@sector.route("/academic")
@login_required
def academic():
    ctx = _get_context()
    ctx["stats"] = {
        "notes": "Academic environment secure — monitoring students and devices.",
        "devices_online": ctx["total_devices"],
        "users_active": ctx["total_users"],
    }
    return render_template("sectors/academic_dashboard.html", **ctx)


@sector.route("/healthcare")
@login_required
def healthcare():
    ctx = _get_context()
    ctx["stats"] = {
        "notes": "Healthcare systems operational — patient data protected.",
        "devices_online": ctx["total_devices"],
        "users_active": ctx["total_users"],
    }
    return render_template("sectors/healthcare_dashboard.html", **ctx)


@sector.route("/hospitality")
@login_required
def hospitality():
    ctx = _get_context()

    # Add placeholder data for hospitality-specific metrics
    ctx.update({
        "metrics": {
            "active_pos": 8,
            "incidents": 2,
            "guest_complaints": 1,
            "security_alerts": 0
        }
    })

    return render_template("sectors/hospitality_dashboard.html", **ctx)