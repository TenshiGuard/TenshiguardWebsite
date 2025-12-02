# app/models/ai_process.py

from app.extensions import db
from datetime import datetime

class AIProcessEvent(db.Model):
    __tablename__ = "ai_process_event"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)

    process_name = db.Column(db.String(256))
    command_line = db.Column(db.String(1024))

    severity = db.Column(db.String(20))
    rule_id = db.Column(db.String(50))

    score = db.Column(db.Integer, default=0)

    # FIXED: use default=dict, not {}
    findings_json = db.Column(db.JSON, default=dict)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "process_name": self.process_name,
            "command_line": self.command_line,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "score": self.score,
            "findings": self.findings_json,
            "created_at": self.created_at.isoformat(),
        }
