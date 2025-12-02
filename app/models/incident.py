from datetime import datetime, timezone
from app.extensions import db

class Incident(db.Model):
    __tablename__ = "incident"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organization.id", ondelete="CASCADE"),
        nullable=False
    )

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), nullable=False, default="open")

    risk_score = db.Column(db.Integer, nullable=True)
    mitre_tag = db.Column(db.String(120), nullable=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        onupdate=lambda: datetime.now(timezone.utc)
    )

    # FIXED RELATIONSHIP
    events = db.relationship(
        "Event",
        back_populates="incident",
        lazy=True,
        cascade="all, delete-orphan"
    )
