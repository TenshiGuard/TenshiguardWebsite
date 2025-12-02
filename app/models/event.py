from datetime import datetime, timezone
from app.extensions import db

class Event(db.Model):
    __tablename__ = "event"

    id = db.Column(db.Integer, primary_key=True)

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organization.id", ondelete="CASCADE"),
        nullable=False
    )

    device_id = db.Column(
        db.Integer,
        db.ForeignKey("device.id", ondelete="SET NULL"),
        nullable=True
    )

    # ---- Core event metadata ----
    event_type = db.Column(db.String(50), nullable=False)      # auth, process, file, network, threat
    category   = db.Column(db.String(50), nullable=True)       # same as ai category or event class
    severity   = db.Column(db.String(20), nullable=False)      # info, low, medium, high, critical

    # ---- NEW FIELDS: required by AI ingest pipeline ----
    action     = db.Column(db.String(120), nullable=True)      # failed_login, executed, opened_file, etc.
    mac        = db.Column(db.String(50), nullable=True)
    detail     = db.Column(db.Text, nullable=True)
    message    = db.Column(db.Text, nullable=True)
    mitigation = db.Column(db.Text, nullable=True)  # Actions taken or recommended
    source_ip  = db.Column(db.String(50), nullable=True)

    # ---- Correlation + Incident Fields ----
    correlation_id     = db.Column(db.Integer, nullable=True)
    correlation_key    = db.Column(db.String(255), nullable=True)
    correlation_score  = db.Column(db.Integer, default=0)

    # *** ADD THIS BLOCK ***
    incident_id = db.Column(
    db.Integer,
    db.ForeignKey("incident.id", ondelete="SET NULL"),
    nullable=True
)

    # *** END BLOCK ***

    # ---- Timestamp ----
    ts = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    # ---- Relationships ----
    device = db.relationship(
        "Device",
        back_populates="events",
        foreign_keys=[device_id]
    )

    organization = db.relationship(
        "Organization",
        back_populates="events",
        foreign_keys=[organization_id]
    )

    # optional: relationship to Incident (not required but recommended)
    incident = db.relationship(
       "Incident",
       back_populates="events",
      lazy=True
   )


    def __repr__(self):
        return f"<Event {self.id} {self.event_type} {self.severity}>"
