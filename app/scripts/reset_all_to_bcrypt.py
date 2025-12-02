# app/scripts/reset_all_to_bcrypt.py
"""
One-click script to rehash all user passwords in TenshiGuard
to bcrypt format. Use only in local/development environments.
"""

from app import create_app
from app.extensions import db, bcrypt
from app.models.user import User

def reset_all_to_bcrypt(default_password="Tenshi123!"):
    """Rehash all user passwords to bcrypt format."""
    app = create_app()
    with app.app_context():
        users = User.query.all()
        if not users:
            print("⚠️  No users found in database.")
            return
        
        print(f"🧠 Found {len(users)} users. Rehashing to bcrypt...\n")

        updated = 0
        for user in users:
            # Skip users that already use bcrypt ($2b$ prefix)
            if user.password_hash and user.password_hash.startswith("$2"):
                print(f"✔️  {user.email} already uses bcrypt — skipped.")
                continue
            
            # Generate a new bcrypt hash
            new_hash = bcrypt.generate_password_hash(default_password).decode("utf-8")
            user.password_hash = new_hash
            db.session.add(user)
            updated += 1
            print(f"🔄 Updated {user.email} → new bcrypt hash set.")

        db.session.commit()
        print(f"\n✅ Done! {updated} accounts reset to bcrypt.")
        print(f"👉 Default login password: {default_password}\n")


if __name__ == "__main__":
    confirm = input("⚠️ This will overwrite ALL user passwords. Continue? (yes/no): ")
    if confirm.lower() == "yes":
        reset_all_to_bcrypt()
    else:
        print("❌ Cancelled. No changes made.")
