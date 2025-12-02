from datetime import datetime
from flask_login import UserMixin
from app.extensions import db
import secrets

# ============================================================
# 🏢 ORGANIZATION MODEL
# ============================================================
class Organization(db.Model):
    __tablename__ = "organization"

    # 🔹 Core Fields
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        default=lambda: secrets.token_hex(16)
    )  # Used for installer and API authentication
    name = db.Column(db.String(100), nullable=False)
    sector = db.Column(db.String(50), default="academic")
    location = db.Column(db.String(150), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # 🔹 Subscription Link
    subscription_id = db.Column(db.Integer, db.ForeignKey("subscription.id"))

    # 🔹 SOS Alert Contact Fields
    alert_email = db.Column(db.String(255), nullable=True)
    alert_phone = db.Column(db.String(50), nullable=True)

    # 🔹 Relationships
    users = db.relationship("User", backref="organization", lazy=True)
    alerts = db.relationship("Alert", backref="organization", lazy=True)
    alert_pref = db.relationship("AlertPreference", backref="organization", uselist=False)

    # 🔹 Utility Methods
    def __repr__(self):
        return f"<Organization {self.name} ({self.sector})>"

    def get_alert_contacts(self):
        """Return tuple (email, phone) for notifications."""
        return (self.alert_email, self.alert_phone)


# ============================================================
# 👤 USER MODEL
# ============================================================
class User(UserMixin, db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    # Role and sector info
    role = db.Column(db.String(50), default="user")  # user | admin | super_admin
    sector = db.Column(db.String(50), default="academic")

    # Link to organization
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"))

    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Convenience helper
    def is_admin(self):
        return self.role in ["admin", "super_admin"]

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# ============================================================
# 💳 SUBSCRIPTION MODEL
# ============================================================
class Subscription(db.Model):
    __tablename__ = "subscription"

    id = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(50), default="basic")  # basic | professional | enterprise
    status = db.Column(db.String(20), default="active")
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)
    sos_enabled = db.Column(db.Boolean, default=False)

    # One-to-many relationship: Subscription → Organizations
    organizations = db.relationship("Organization", backref="subscription", lazy=True)

    def __repr__(self):
        return f"<Subscription {self.plan}>"


# ============================================================
# 🚨 ALERT MODEL
# ============================================================
class Alert(db.Model):
    __tablename__ = "alert"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"))
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default="info")  # info | low | medium | high | critical
    category = db.Column(db.String(50), default="general")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "category": self.category,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self):
        return f"<Alert {self.severity.upper()} {self.title[:30]}>"


# ============================================================
# ⚙️ ALERT PREFERENCE MODEL (Per Organization)
# ============================================================
class AlertPreference(db.Model):
    __tablename__ = "alert_preference"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), unique=True, nullable=False)

    min_severity = db.Column(db.String(20), default="medium")  # info | low | medium | high | critical
    categories_csv = db.Column(db.Text, default="system,network,login,malware,data_theft,compliance")
    email_enabled = db.Column(db.Boolean, default=True)
    sms_enabled = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Category property helpers
    @property
    def categories(self):
        """Return list of categories."""
        return [c.strip() for c in (self.categories_csv or "").split(",") if c.strip()]

    @categories.setter
    def categories(self, value):
        """Store list as CSV string."""
        if isinstance(value, (list, tuple)):
            self.categories_csv = ",".join(sorted(set(str(v).strip() for v in value if v)))
        elif isinstance(value, str):
            self.categories_csv = value
        else:
            self.categories_csv = ""

    def to_dict(self):
        return {
            "organization_id": self.organization_id,
            "min_severity": self.min_severity,
            "categories": self.categories,
            "email_enabled": self.email_enabled,
            "sms_enabled": self.sms_enabled,
        }

    def __repr__(self):
        return f"<AlertPref Org={self.organization_id} min={self.min_severity}>"
