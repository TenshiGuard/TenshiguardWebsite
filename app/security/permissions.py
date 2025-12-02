# app/security/permissions.py
from functools import wraps
from flask import abort, flash, redirect, url_for, jsonify, current_app
from flask_login import current_user, login_required

def role_required(*roles):
    """Protect a view so only certain roles can access."""
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                if "api" in str(view.__module__):
                    return jsonify({"status": "error", "message": "Authentication required"}), 401
                return current_app.login_manager.unauthorized()
            
            if current_user.role not in roles:
                if "api" in str(view.__module__):
                    return jsonify({"status": "error", "message": "Access denied"}), 403
                
                flash("You do not have permission to view this page.", "danger")
                return redirect(url_for("dashboard.index"))
            
            return view(*args, **kwargs)
        return wrapped
    return decorator
