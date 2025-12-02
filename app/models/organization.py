# ============================================================
# 🧩 TenshiGuard Organization Model — Final Stable Version
# ============================================================
from datetime import datetime
from secrets import token_hex
from sqlalchemy import event
from app.extensions import db


class Organization(db.Model):
    __tablename__ = "organization"

    # ─────────────── Core Fields ───────────────
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sector = db.Column(db.String(50), default="academic")
    location = db.Column(db.String(150))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ─────────────── Subscription Link ───────────────
    subscription_id = db.Column(db.Integer, db.ForeignKey("subscription.id"))
    subscription = db.relationship("Subscription", back_populates="organizations")

    # ─────────────── SOS Alert Contact Fields ───────────────
    alert_email = db.Column(db.String(255))
    alert_phone = db.Column(db.String(50))

    # ─────────────── Agent / Devices ───────────────
    agent_token = db.Column(db.String(80), unique=True, index=True)

    # ─────────────── Relationships ───────────────
    users = db.relationship("User", backref="organization", lazy=True)

    alerts = db.relationship(
        "Alert",
        back_populates="organization",
        lazy=True,
        cascade="all, delete-orphan",
    )

    alert_pref = db.relationship(
        "AlertPreference",
        back_populates="organization",
        uselist=False,
        cascade="all, delete-orphan",
    )

    devices = db.relationship(
        "Device",
        back_populates="organization",
        lazy=True,
        cascade="all, delete-orphan",
    )

    events = db.relationship("Event", back_populates="organization", cascade="all, delete-orphan")




    # ─────────────── Utility Methods ───────────────
    def get_alert_contacts(self):
        """Return (email, phone) tuple for notifications."""
        return (self.alert_email, self.alert_phone)

    def to_dict(self):
        """Serialize organization data for admin/API."""
        return {
            "id": self.id,
            "name": self.name,
            "sector": self.sector,
            "location": self.location,
            "alert_email": self.alert_email,
            "alert_phone": self.alert_phone,
            "agent_token": self.agent_token,
            "subscription_id": self.subscription_id,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def __repr__(self):
        return f"<Organization {self.name} ({self.sector})>"


# ─────────────── AUTO TOKEN GENERATION ───────────────
@event.listens_for(Organization, "before_insert")
def generate_sector_token(mapper, connection, target):
    """
    Automatically generate a unique agent token based on sector.
    Example: ACADEMIC-1F3A9E7B... or HEALTH-9D33A6C...
    """
    if not target.agent_token:
        sector_map = {
            "academic": "ACADEMIC",
            "health": "HEALTH",
            "hospitality": "HOSPITALITY",
            "finance": "FINANCE",
            "corporate": "CORP",
        }

        sector_name = (target.sector or "").lower()
        prefix = sector_map.get(sector_name, "ORG")
        target.agent_token = f"{prefix}-{token_hex(12).upper()}"
