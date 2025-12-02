# create_seed_data.py
from app import create_app, db
from app.models.subscription import Subscription
from app.models.organization import Organization
from app.models.user import User

app = create_app()

# =========================================================
# 🚀 Seed Script: TenshiGuard Default Data
# =========================================================
def seed_subscriptions():
    """Creates or updates the 3 main subscription tiers."""

    plans = [
        {
            "name": "Basic",
            "description": "Perfect for small teams that need basic endpoint monitoring and reporting.",
            "price": 0.0,
            "billing_cycle": "monthly",
            "max_users": 5,
            "max_devices": 10,
            "alert_type": "none",
            "features": [
                "Basic dashboard access",
                "Device activity overview",
                "Email-only login alerts",
                "Community support"
            ],
        },
        {
            "name": "Professional",
            "description": "Ideal for growing organizations needing proactive security alerts and detailed analytics.",
            "price": 29.99,
            "billing_cycle": "monthly",
            "max_users": 20,
            "max_devices": 40,
            "alert_type": "email_sms",
            "features": [
                "All Basic features",
                "Bruteforce detection alerts (email + SMS)",
                "User behavior analytics",
                "Scheduled security reports",
                "24/7 email support"
            ],
        },
        {
            "name": "Enterprise",
            "description": "Complete enterprise-grade monitoring with custom alert channels and phone call SOS signals.",
            "price": 99.99,
            "billing_cycle": "monthly",
            "max_users": 9999,
            "max_devices": 9999,
            "alert_type": "phone_call",
            "features": [
                "All Professional features",
                "Full real-time monitoring (malware, unregistered devices, anomalies)",
                "Custom alert rules per department",
                "SOS Phone alerts (auto call)",
                "Dedicated support manager"
            ],
        },
    ]

    for plan_data in plans:
        # Map 'name' from plans dict to 'plan' in Subscription model
        plan_name = plan_data.pop("name")
        plan_data["plan"] = plan_name
        
        # Remove fields not in model if any (description, billing_cycle, max_users, max_devices, alert_type, features are NOT in model shown above)
        # Wait, the model only has: plan, price, status, sos_enabled.
        # The seed script tries to set description, billing_cycle, max_users, etc.
        # I need to check if those columns exist in the DB or if the model file is incomplete/outdated.
        # Based on the error "Entity namespace for "subscription" has no property "name"", it seems the model is indeed what I saw.
        # But the seed script has a lot of fields.
        # Let's check the database schema or just fit the model.
        # The model has: plan, price, status, sos_enabled.
        # The seed script has: name, description, price, billing_cycle, max_users, max_devices, alert_type, features.
        
        # I will only set the fields that exist in the model.
        # plan -> plan
        # price -> price
        # status -> 'active' (default)
        # sos_enabled -> True if price > 0?
        
        existing_plan = Subscription.query.filter_by(plan=plan_name).first()
        if existing_plan:
            existing_plan.price = plan_data["price"]
            existing_plan.sos_enabled = (plan_name.lower() in ["professional", "enterprise"])
            print(f"🔄 Updated existing plan: {existing_plan.plan}")
        else:
            new_plan = Subscription(
                plan=plan_name,
                price=plan_data["price"],
                status="active",
                sos_enabled=(plan_name.lower() in ["professional", "enterprise"])
            )
            db.session.add(new_plan)
            print(f"🆕 Created new plan: {new_plan.plan}")

    db.session.commit()
    print("✅ Subscription plans seeded successfully.")


# =========================================================
# 🏫 Default Organization (optional)
# =========================================================
def seed_org():
    org = Organization.query.filter_by(name="TenshiGuard Academy").first()
    if org:
        print("✔ Organization already exists — skipping.")
        return org

    org = Organization(
        name="TenshiGuard Academy",
        sector="Academic",
        location="Canada"
    )
    db.session.add(org)
    db.session.commit()
    print("✅ Default organization created successfully.")
    return org


# =========================================================
# 👤 Default Admin (optional)
# =========================================================
def seed_admin(org):
    admin = User.query.filter_by(email="admin@tenshiguard.com").first()
    if admin:
        print("✔ Admin user already exists — skipping.")
        return

    admin = User(
        username="admin",
        email="admin@tenshiguard.com",
        role="admin",
        sector="Academic",
        organization_id=org.id,
    )
    admin.set_password("Admin@2025")
    db.session.add(admin)
    db.session.commit()
    print("✅ Admin account created: admin@tenshiguard.com / Admin@2025")


# =========================================================
# 👤 Test User (Requested by User)
# =========================================================
def seed_test_user(org):
    email = "testorg1@gmail.com"
    user = User.query.filter_by(email=email).first()
    if user:
        print(f"✔ Test user {email} already exists — skipping.")
        return

    user = User(
        username="testorg1",
        email=email,
        role="admin", # Making admin for full access testing
        sector="Academic",
        organization_id=org.id,
    )
    user.set_password("12345678@Testorg")
    db.session.add(user)
    db.session.commit()
    print(f"✅ Test user created: {email} / 12345678@Testorg")


# =========================================================
# 🧠 Main Runner
# =========================================================
if __name__ == "__main__":
    with app.app_context():
        print("\n🚀 Starting TenshiGuard Database Seeding...\n")
        seed_subscriptions()

        org = seed_org()
        seed_admin(org)
        seed_test_user(org)

        print("\n🎉 TenshiGuard Database Seeding Complete!\n")
        print("🔑 Test Admin Login:")
        print("   Email: admin@tenshiguard.com")
        print("   Password: Admin@2025\n")
        print("------------------------------------------------------")
        print("If you make schema changes, run:")
        print("   flask db upgrade && python3 create_seed_data.py")
        print("------------------------------------------------------")
