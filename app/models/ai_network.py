# app/models/ai_network.py

from app.extensions import db
from datetime import datetime

class AINetworkEvent(db.Model):
    __tablename__ = "ai_network_event"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)

    dest_ip = db.Column(db.String(64))
    dest_port = db.Column(db.Integer)

    severity = db.Column(db.String(20))
    rule_id = db.Column(db.String(50))

    score = db.Column(db.Integer, default=0)

    # FIXED: Safe default
    findings_json = db.Column(db.JSON, default=dict)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "score": self.score,
            "findings": self.findings_json,
            "created_at": self.created_at.isoformat(),
        }
