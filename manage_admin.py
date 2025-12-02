from app import create_app, db, bcrypt
from app.models import User

app = create_app()

with app.app_context():
    user = User.query.filter_by(username="admin").first()
    if user:
        print(f"User 'admin' found. Email: {user.email}")
        user.password_hash = bcrypt.generate_password_hash("admin").decode("utf-8")
        db.session.commit()
        print("Password reset to 'admin'.")
    else:
        print("User 'admin' NOT found. Creating...")
        hashed_pw = bcrypt.generate_password_hash("admin").decode("utf-8")
        new_user = User(
            username="admin",
            email="admin@tenshiguard.ai",
            password_hash=hashed_pw,
            role="admin"
        )
        db.session.add(new_user)
        db.session.commit()
        print("User 'admin' created with password 'admin'.")
