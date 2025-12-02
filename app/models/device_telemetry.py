# app/models/device_telemetry.py
from datetime import datetime, timezone
from app.extensions import db


class DeviceTelemetry(db.Model):
    """
    Time-series telemetry per device.
    Used for CPU/MEM charts and AI anomaly detection.
    """
    __tablename__ = "device_telemetry"

    id = db.Column(db.Integer, primary_key=True)

    # Link to Device
    device_id = db.Column(
        db.Integer,
        db.ForeignKey("device.id", name="fk_telemetry_device"),
        nullable=False,
        index=True,
    )

    # When this snapshot was taken (UTC)
    ts = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # Basic metrics
    cpu_percent = db.Column(db.Float, default=0.0)
    mem_percent = db.Column(db.Float, default=0.0)

    # Agent version that reported this
    agent_version = db.Column(db.String(32), default="0.1-sim")

    # Optional extra JSON (future expansion: disk, network, etc.)
    extra = db.Column(db.JSON, nullable=True)

    # Relationship back to Device
    device = db.relationship("Device", back_populates="telemetry")

    def to_dict(self):
        return {
            "id": self.id,
            "device_id": self.device_id,
            "ts": self.ts.strftime("%Y-%m-%d %H:%M:%S UTC") if self.ts else None,
            "cpu_percent": float(self.cpu_percent or 0.0),
            "mem_percent": float(self.mem_percent or 0.0),
            "agent_version": self.agent_version,
            "extra": self.extra or {},
        }

    def __repr__(self):
        return f"<DeviceTelemetry device={self.device_id} cpu={self.cpu_percent} mem={self.mem_percent}>"
