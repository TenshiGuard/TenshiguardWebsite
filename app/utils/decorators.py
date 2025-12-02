from functools import wraps
from flask import redirect, url_for, flash, jsonify
from flask_login import current_user

def role_required(role_name):
    """
    Restricts route access to users with a specific role.
    If used on an API route, returns JSON instead of redirect.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure user is logged in
            if not current_user.is_authenticated:
                if "api" in str(f.__module__):
                    return jsonify({"status": "error", "message": "Authentication required"}), 401
                else:
                    flash("You must be logged in to access this page.", "warning")
                    return redirect(url_for("auth.login"))

            # Check role
            if getattr(current_user, "role", None) != role_name:
                if "api" in str(f.__module__):
                    return jsonify({"status": "error", "message": "Access denied"}), 403
                else:
                    flash("You do not have permission to view this page.", "danger")
                    return redirect(url_for("dashboard.index"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator
