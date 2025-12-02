from datetime import datetime, timezone
from app.extensions import db

class AILearnedRule(db.Model):
    __tablename__ = "ai_learned_rule"

    id = db.Column(db.Integer, primary_key=True)
    rule_name = db.Column(db.String(255), unique=True, nullable=False)
    weight_modifier = db.Column(db.Float, default=0.0)
    feedback_count = db.Column(db.Integer, default=0)
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<AILearnedRule {self.rule_name} ({self.weight_modifier})>"
