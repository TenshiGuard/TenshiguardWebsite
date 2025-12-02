from app import create_app, db
from app.models import User, Organization
from werkzeug.security import check_password_hash

app = create_app()

with app.app_context():
    admin = User.query.filter_by(email="admin@tenshiguard.ai").first()
    if admin:
        print(f"Admin found: {admin.username}")
        print(f"Role: {admin.role}")
        print(f"Org ID: {admin.organization_id}")
        print(f"Password Valid: {check_password_hash(admin.password_hash, 'Admin123!')}")
        
        org = Organization.query.get(admin.organization_id)
        if org:
            print(f"Org found: {org.name}")
            print(f"Agent Token: {org.agent_token}")
        else:
            print("Org NOT found!")
    else:
        print("Admin NOT found!")
