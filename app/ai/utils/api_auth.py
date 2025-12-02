# app/utils/api_auth.py
# ============================================================
# 🔐 Simple API Key Authentication for Backend / Dashboard APIs
# ============================================================

import hmac
from functools import wraps

from flask import current_app, request, jsonify


def _get_provided_key() -> str:
    """
    Get API key from:
      - X-API-KEY header
      - X-TENSHIGUARD-KEY header
      - api_key=query param (for quick curl tests)
    """
    header_key = request.headers.get("X-API-KEY") or request.headers.get("X-TENSHIGUARD-KEY")
    if header_key:
        return header_key.strip()

    query_key = request.args.get("api_key")
    if query_key:
        return query_key.strip()

    return ""


def require_api_key(view_func):
    """
    Decorator to protect backend APIs with a shared secret key.

    Behavior:
      - If DASHBOARD_API_KEY is empty/None:
            ⇒ allow all requests (dev mode).
      - Else:
            ⇒ require valid key, otherwise 401 JSON error.
    """
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        expected = (current_app.config.get("DASHBOARD_API_KEY") or "").strip()

        # Dev mode: key not configured → allow but warn in logs
        if not expected:
            current_app.logger.warning(
                "[api_auth] DASHBOARD_API_KEY not set — allowing request without key."
            )
            return view_func(*args, **kwargs)

        provided = _get_provided_key()

        if not provided or not hmac.compare_digest(provided, expected):
            return (
                jsonify(
                    {
                        "ok": False,
                        "error": "Unauthorized — invalid or missing API key.",
                    }
                ),
                401,
            )

        return view_func(*args, **kwargs)

    return wrapped
