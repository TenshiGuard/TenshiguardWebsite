# ============================================================
# 🧩 TenshiGuard User Model — Stable Production Version
# ============================================================
from datetime import datetime
from flask_login import UserMixin
from app.extensions import db, bcrypt

class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")  # user | admin | sector_admin
    sector = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_enabled = db.Column(db.Boolean, default=True)

    # Foreign Key
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"))

    # ============================================================
    # 🔹 Security Helpers
    # ============================================================
    def set_password(self, password: str):
        """Hashes and stores the given password."""
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password: str) -> bool:
        """Verifies a password against the stored hash."""
        return bcrypt.check_password_hash(self.password_hash, password)

    # ============================================================
    # 🔹 Utility Methods
    # ============================================================
    def to_dict(self):
        """Returns a dictionary version (safe for API use)."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "sector": self.sector,
            "organization_id": self.organization_id,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
