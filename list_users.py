from app import create_app
from app.models import User

def list_users():
    app = create_app()
    with app.app_context():
        users = User.query.all()
        for u in users:
            print(f"User: {u.username}, Email: {u.email}, Role: {u.role}")

if __name__ == "__main__":
    list_users()
