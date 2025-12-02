from app import create_app
from app.models import User, Organization

def check_orgs():
    app = create_app()
    with app.app_context():
        # Check Admin user's org
        admin = User.query.filter_by(email="admin@tenshiguard.com").first()
        if admin:
            print(f"User: {admin.email} | Org ID: {admin.organization_id}")
            if admin.organization:
                 print(f"Org Name: {admin.organization.name}")
        
        # Check the first org (used by simulation)
        first_org = Organization.query.first()
        print(f"First Org (Simulation Target): ID {first_org.id} | Name: {first_org.name}")

if __name__ == "__main__":
    check_orgs()
