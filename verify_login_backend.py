from app import create_app, db, bcrypt
from app.models.user import User

app = create_app()

with app.app_context():
    print("--- Verifying Users ---")
    
    # Check Admin
    admin = User.query.filter_by(email="admin@tenshiguard.com").first()
    if admin:
        print(f"Admin found: {admin.email}")
        is_valid = bcrypt.check_password_hash(admin.password_hash, "Admin@2025")
        print(f"Admin password valid: {is_valid}")
    else:
        print("Admin NOT found")

    # Check Test User
    test_user = User.query.filter_by(email="testorg1@gmail.com").first()
    if test_user:
        print(f"Test User found: {test_user.email}")
        is_valid = bcrypt.check_password_hash(test_user.password_hash, "12345678@Testorg")
        print(f"Test User password valid: {is_valid}")
    else:
        print("Test User NOT found")
