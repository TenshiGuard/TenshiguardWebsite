from app import create_app
from app.models import User

def check_sub():
    app = create_app()
    with app.app_context():
        user = User.query.filter_by(email="admin@tenshiguard.com").first()
        if user and user.organization:
            sub = user.organization.subscription
            if sub:
                print(f"Plan: {sub.plan}, SOS Enabled: {sub.sos_enabled}")
            else:
                print("No subscription found.")
        else:
            print("User or Org not found.")

if __name__ == "__main__":
    check_sub()
