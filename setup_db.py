from app import create_app, db
from app.models.user import User
from app.models.organization import Organization
from app.models.subscription import Subscription

app = create_app()

with app.app_context():
    print("Creating tables...")
    db.create_all()
    
    # Create Subscription
    sub = Subscription.query.filter_by(plan="enterprise").first()
    if not sub:
        sub = Subscription(plan="enterprise", status="active", sos_enabled=True)
        db.session.add(sub)
        db.session.commit()
        print("Subscription created.")

    # Create Organization
    org = Organization.query.filter_by(name="TenshiGuard HQ").first()
    if not org:
        org = Organization(name="TenshiGuard HQ", sector="tech", agent_token="tg-admin-token", subscription_id=sub.id)
        db.session.add(org)
        db.session.commit()
        print("Organization created.")
    else:
        # Ensure org has subscription
        if not org.subscription_id:
            org.subscription_id = sub.id
            db.session.commit()
            print("Linked existing Org to Subscription.")

    # Create Admin User
    admin = User.query.filter_by(email="admin@tenshiguard.com").first()
    if not admin:
        admin = User(
            username="Admin",
            email="admin@tenshiguard.com",
            role="admin",
            organization_id=org.id,
            is_enabled=True
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
        print("Admin user created: admin@tenshiguard.com / admin123")
    else:
        print("Admin user already exists.")
