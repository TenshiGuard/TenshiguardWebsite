# app/models/subscription.py
from datetime import datetime
from app.extensions import db

class Subscription(db.Model):
    __tablename__ = "subscription"

    id = db.Column(db.Integer, primary_key=True)
    plan = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default="inactive")
    sos_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # ✅ Relationship (one subscription -> many organizations possible)
    organizations = db.relationship(
        "Organization",
        back_populates="subscription",
        lazy=True,
        foreign_keys="[Organization.subscription_id]",
    )

    def __repr__(self):
        return f"<Subscription {self.plan} ({self.status})>"
