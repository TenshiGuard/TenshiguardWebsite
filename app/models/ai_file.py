# app/models/ai_file.py

from app.extensions import db
from datetime import datetime

class AIFileScan(db.Model):
    __tablename__ = "ai_file_scan"

    id = db.Column(db.Integer, primary_key=True)

    device_id = db.Column(db.Integer, db.ForeignKey("device.id"), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey("organization.id"), nullable=False)

    file_hash = db.Column(db.String(128), nullable=False)
    file_path = db.Column(db.String(512))

    severity = db.Column(db.String(20))
    rule_id = db.Column(db.String(50))
    rule_name = db.Column(db.String(120))

    score = db.Column(db.Integer, default=0)

    # Use default=dict for safety
    findings_json = db.Column(db.JSON, default=dict)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "file_hash": self.file_hash,
            "file_path": self.file_path,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "score": self.score,
            "findings": self.findings_json,
            "created_at": self.created_at.isoformat(),
        }
