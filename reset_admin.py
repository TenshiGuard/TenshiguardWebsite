from app import create_app, db
from app.models import User, Organization
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    # Check if admin exists
    admin = User.query.filter_by(email="admin@tenshiguard.ai").first()
    
    if not admin:
        print("Admin user not found. Creating...")
        # Ensure org exists
        org = Organization.query.first()
        if not org:
            org = Organization(name="TenshiGuard HQ", sector="cybersecurity")
            db.session.add(org)
            db.session.commit()
            
        admin = User(
            username="admin",
            email="admin@tenshiguard.ai",
            role="admin",
            organization_id=org.id
        )
        db.session.add(admin)
    
    # Reset password using model method (uses bcrypt)
    admin.set_password("Admin123!")
    db.session.commit()
    print("Admin password reset to: Admin123! (Bcrypt)")
