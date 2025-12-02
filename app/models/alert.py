# ============================================================
# 🧩 TenshiGuard Alert Models — Final Stable Version
# ============================================================
from datetime import datetime, timezone
from app.extensions import db

# ----------------- ALERT MODEL -----------------
class Alert(db.Model):
    __tablename__ = "alert"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organization.id", name="fk_alert_organization"),
        nullable=False
    )

    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    severity = db.Column(db.String(20), default="info")      # info | low | medium | high | critical
    category = db.Column(db.String(50), default="general")   # e.g. "auth", "system", etc.
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    sent_email = db.Column(db.Boolean, default=False)
    sent_sms = db.Column(db.Boolean, default=False)

    # 🧠 Adaptive AI Feedback
    feedback = db.Column(db.String(20), default="pending")  # pending | true_positive | false_positive
    feedback_at = db.Column(db.DateTime, nullable=True)
    adjusted_score = db.Column(db.Float, default=0.0)

    # Relationship
    # Relationship
    organization = db.relationship("Organization", back_populates="alerts")
    
    device_id = db.Column(
        db.Integer,
        db.ForeignKey("device.id", ondelete="SET NULL"),
        nullable=True
    )
    device = db.relationship("Device", backref="alerts")

    def __repr__(self):
        return f"<Alert id={self.id} severity={self.severity}>"

    def to_dict(self):
        """Convert alert record to dict for JSON response."""
        created = self.created_at or datetime.now(timezone.utc)
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "category": self.category,
            "created_at": created.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "sent_email": bool(self.sent_email),
            "sent_sms": bool(self.sent_sms),
        }


# ----------------- ALERT PREFERENCE MODEL -----------------
class AlertPreference(db.Model):
    __tablename__ = "alert_preference"

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organization.id", name="fk_alert_pref_organization"),
        nullable=False,
        index=True,
    )

    # Notification settings
    email_enabled = db.Column(db.Boolean, default=True)
    sms_enabled = db.Column(db.Boolean, default=False)
    email_to = db.Column(db.String(255))
    sms_to = db.Column(db.String(50))

    # Filtering & behavior
    min_severity = db.Column(db.String(20), default="high")  # info | medium | high | critical
    always_on = db.Column(db.Boolean, default=True)
    off_start_hour = db.Column(db.Integer, default=19)
    off_end_hour = db.Column(db.Integer, default=8)

    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    organization = db.relationship("Organization", back_populates="alert_pref")

    def __repr__(self):
        return f"<AlertPreference org={self.organization_id} min={self.min_severity}>"

    def to_dict(self):
        """Return a JSON-safe representation of this preference."""
        ts = self.updated_at or datetime.utcnow()
        return {
            "email_enabled": bool(self.email_enabled),
            "sms_enabled": bool(self.sms_enabled),
            "email_to": self.email_to or "",
            "sms_to": self.sms_to or "",
            "min_severity": (self.min_severity or "high").lower(),
            "always_on": bool(self.always_on),
            "off_start_hour": int(self.off_start_hour or 19),
            "off_end_hour": int(self.off_end_hour or 8),
            "updated_at": ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
