# ============================================================
# 🧩 TenshiGuard Authentication Routes — Final Integrated Version
# ============================================================
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from app.extensions import db, bcrypt
from app.models.user import User
from app.models.organization import Organization

auth = Blueprint("auth", __name__)

# ---------------------------
# LOGIN
# ---------------------------
@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = User.query.filter_by(email=email).first()

        # --- Validation ---
        if not user:
            flash("❌ No account found with this email.", "danger")
            return redirect(url_for("auth.login"))

        if not user.is_enabled:
            flash("⚠️ Your account is disabled. Contact admin.", "warning")
            return redirect(url_for("auth.login"))

        if not bcrypt.check_password_hash(user.password_hash, password):
            flash("⚠️ Incorrect password. Please try again.", "warning")
            return redirect(url_for("auth.login"))

        # --- Login success ---
        login_user(user)
        flash(f"Welcome back, {user.username}!", "success")
        return redirect(url_for("dashboard.index"))

    return render_template("auth/login.html")


# ---------------------------
# LOGOUT
# ---------------------------
@auth.route("/logout")
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash(f"👋 {username}, you have been logged out.", "info")
    return redirect(url_for("auth.login"))


# ---------------------------
# REGISTER ORGANIZATION
# ---------------------------
@auth.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register_org.html")

    org_name = (request.form.get("org_name") or "").strip()
    sector = (request.form.get("sector") or "").strip().lower()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm_password") or ""
    plan = (request.form.get("plan") or "basic").strip().lower()

    if not all([org_name, sector, email, password, confirm]):
        flash("All fields are required.", "danger")
        return redirect(url_for("auth.register"))

    if password != confirm:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("auth.register"))

    if User.query.filter_by(email=email).first():
        flash("Email already registered.", "warning")
        return redirect(url_for("auth.register"))

    # Create organization
    org = Organization(name=org_name, sector=sector)
    db.session.add(org)
    db.session.flush()

    # Create admin user
    user = User(
        username=email.split("@")[0],
        email=email,
        role="admin",
        organization_id=org.id,
        is_enabled=True,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    # Redirect to success page
    return render_template(
        "auth/success.html",
        org_name=org_name,
        plan=plan
    )


# ---------------------------
# FORGOT PASSWORD
# ---------------------------
@auth.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("auth/forgot_password.html")

    email = (request.form.get("email") or "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        flash("No account found with this email.", "warning")
        return redirect(url_for("auth.forgot_password"))

    flash("📩 Password reset link has been sent to your email (mock).", "info")
    return redirect(url_for("auth.login"))


# ---------------------------
# RESET PASSWORD (placeholder)
# ---------------------------
@auth.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if request.method == "GET":
        return render_template("auth/reset_password.html")

    password = request.form.get("password")
    confirm = request.form.get("confirm")

    if not password or not confirm or password != confirm:
        flash("Passwords do not match.", "danger")
        return redirect(url_for("auth.reset_password"))

    flash("✅ Password updated successfully (mock).", "success")
    return redirect(url_for("auth.login"))
