# app/models/ai_event.py

from app.extensions import db
from datetime import datetime

class AIEvent(db.Model):
    __tablename__ = "ai_event"   # <-- FIXED

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)

    event_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    score = db.Column(db.Integer, default=0)

    findings_json = db.Column(db.JSON, default={})
    raw_json = db.Column(db.JSON, default={})

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "event_type": self.event_type,
            "severity": self.severity,
            "score": self.score,
            "findings": self.findings_json,
            "raw": self.raw_json,
            "created_at": self.created_at.isoformat(),
        }
