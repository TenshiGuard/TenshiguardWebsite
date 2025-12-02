# app/routes/register_flow.py

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user
from app.extensions import db, bcrypt
from app.models import Organization, User, Subscription

# ------------------------------
# Blueprint Setup
# ------------------------------
register_flow = Blueprint("register_flow", __name__, url_prefix="/register")


# ------------------------------
# ORGANIZATION REGISTRATION
# ------------------------------
@register_flow.route("/org", methods=["GET", "POST"])
def org():
    if request.method == "POST":
        org_name = request.form.get("org_name", "").strip()
        sector = request.form.get("sector", "").strip()
        plan = request.form.get("plan", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # --- Basic Validation ---
        if not all([org_name, sector, plan, email, password]):
            flash("All fields are required!", "danger")
            return redirect(url_for("register_flow.org"))

        # --- Duplication Checks ---
        if Organization.query.filter_by(name=org_name).first():
            flash("Organization already exists.", "warning")
            return redirect(url_for("register_flow.org"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("register_flow.org"))

        # --- Create Subscription First ---
        plan_prices = {"basic": 0.0, "professional": 49.0, "enterprise": 99.0}
        sos_enabled = plan in ["professional", "enterprise"]

        subscription = Subscription(
            plan=plan,
            price=plan_prices.get(plan, 0.0),
            status="active",
            sos_enabled=sos_enabled,
        )
        db.session.add(subscription)
        db.session.commit()

        # --- Create Organization & Link Subscription ---
        new_org = Organization(
            name=org_name,
            sector=sector,
            subscription_id=subscription.id,
        )
        db.session.add(new_org)
        db.session.commit()

        # --- Create Admin User ---
        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(
            username=f"{org_name}_admin",
            email=email,
            password_hash=hashed_pw,
            role="admin",
            organization_id=new_org.id,
            sector=sector,
        )
        db.session.add(new_user)
        db.session.commit()

        # --- Auto-login the new admin ---
        login_user(new_user)

        # --- Store Info in Session ---
        session["org_name"] = org_name
        session["plan"] = plan
        session["sector"] = sector

        flash(f"✅ {org_name} registered successfully!", "success")
        return redirect(url_for("register_flow.success"))

    return render_template("auth/register_org.html")


# ------------------------------
# SUCCESS PAGE
# ------------------------------
@register_flow.route("/success")
def success():
    org_name = session.get("org_name", "Your Organization")
    plan = session.get("plan", "basic")
    flash("Welcome to your TenshiGuard Dashboard!", "success")
    return render_template("auth/success.html", org_name=org_name, plan=plan)
