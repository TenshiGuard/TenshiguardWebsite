# app/models/ai_risk_score.py

from app.extensions import db
from datetime import datetime

class AIRiskScore(db.Model):
    __tablename__ = "ai_risk_score"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)

    score = db.Column(db.Integer, default=0)
    highest_severity = db.Column(db.String(20), default="low")

    summary_json = db.Column(db.JSON, default=dict)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "organization_id": self.organization_id,
            "score": self.score,
            "highest_severity": self.highest_severity,
            "summary": self.summary_json,
            "created_at": self.created_at.isoformat(),
        }
