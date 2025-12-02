from datetime import datetime
from app.extensions import db


class AISignal(db.Model):
    """
    AI detection result.

    Every time AIEngine flags something, we store a row here
    AND also mirror a summary into Event for Live Events.
    """
    __tablename__ = "ai_signal"

    id = db.Column(db.Integer, primary_key=True)

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organization.id", name="fk_ai_signal_organization"),
        nullable=False,
        index=True,
    )

    device_id = db.Column(
        db.Integer,
        db.ForeignKey("device.id", name="fk_ai_signal_device"),
        nullable=True,
        index=True,
    )

    # What kind of signal is this?
    category = db.Column(db.String(50), nullable=False)     # process/file/network/auth/malware/behavior/...
    severity = db.Column(db.String(20), nullable=False, default="medium")
    rule_name = db.Column(db.String(128), nullable=False)
    detail = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Integer, nullable=False, default=50)
    mac = db.Column(db.String(17), index=True)


    # Optional: mitigation text, to show in AI Insights & Live Events
    mitigation = db.Column(db.Text, nullable=True)

    # Raw payload (original normalized event from agent)
    raw = db.Column(db.JSON, nullable=True)

    ts = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    organization = db.relationship("Organization", backref="ai_signals")
    device = db.relationship("Device", backref="ai_signals")

    def to_dict(self):
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "device_id": self.device_id,
            "category": self.category,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "detail": self.detail or "",
            "risk_score": self.risk_score,
            "mitigation": self.mitigation or "",
            "raw": self.raw or {},
            "ts": self.ts.strftime("%Y-%m-%d %H:%M:%S") if self.ts else None,
        }

    def __repr__(self):
        return f"<AISignal {self.category}:{self.rule_name} ({self.severity})>"
