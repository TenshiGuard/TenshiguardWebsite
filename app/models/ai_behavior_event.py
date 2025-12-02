# app/models/ai_behavior_event.py

from app.extensions import db
from datetime import datetime

class AIBehaviorEvent(db.Model):
    __tablename__ = "ai_behavior_event"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)

    behavior = db.Column(db.String(256))
    severity = db.Column(db.String(20))
    score = db.Column(db.Integer, default=0)

    findings_json = db.Column(db.JSON, default=dict)
    raw_json = db.Column(db.JSON, default=dict)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "organization_id": self.organization_id,
            "behavior": self.behavior,
            "severity": self.severity,
            "score": self.score,
            "findings": self.findings_json,
            "raw": self.raw_json,
            "created_at": self.created_at.isoformat(),
        }
