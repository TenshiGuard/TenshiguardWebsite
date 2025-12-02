# app/security/api_key.py

from functools import wraps
from flask import request, jsonify, current_app
from flask_login import current_user
from app.models.organization import Organization


def require_api_key(f):
    """
    Dual-mode protection:

    1) HEADLESS / API style (curl, agents, external dashboards):
       - Require headers:
         - X-API-KEY
         - X-ORG-ID
       - Validates against Config.DASHBOARD_API_KEY.

    2) DASHBOARD / BROWSER style:
       - If no API key headers, but the user is logged in and has an organization,
         we use current_user.organization.

    In both cases, the wrapped view gets an `org` argument injected.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        org = None

        # -----------------------------
        # Path 1 — API Key + Org Header
        # -----------------------------
        api_key = request.headers.get("X-API-KEY")
        org_id_hdr = request.headers.get("X-ORG-ID")

        if api_key and org_id_hdr:
            expected = current_app.config.get("DASHBOARD_API_KEY")
            if not expected or api_key != expected:
                return jsonify({"ok": False, "message": "Invalid API key"}), 401

            try:
                org_id = int(org_id_hdr)
            except ValueError:
                return jsonify({"ok": False, "message": "Invalid org id"}), 400

            org = Organization.query.get(org_id)
            if not org:
                return jsonify({"ok": False, "message": "Organization not found"}), 400

        # -----------------------------
        # Path 2 — Logged-in Dashboard
        # -----------------------------
        elif current_user.is_authenticated:
            org = getattr(current_user, "organization", None)
            if not org:
                return jsonify({"ok": False, "message": "No organization for user"}), 403

        # -----------------------------
        # No key, no login
        # -----------------------------
        else:
            return jsonify({"ok": False, "message": "Missing API key or not authenticated"}), 401

        # Inject org into the view
        return f(org=org, *args, **kwargs)

    return wrapper
