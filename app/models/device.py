from datetime import datetime, timezone
from app.extensions import db

class Device(db.Model):
    __tablename__ = "device"
    __table_args__ = {"extend_existing": True}

    # ============================================================
    # 🔹 Core Identifiers
    # ============================================================
    id = db.Column(db.Integer, primary_key=True)

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organization.id", name="fk_device_organization"),
        nullable=False
    )

    # Basic info
    device_name = db.Column(db.String(120), nullable=False)
    os = db.Column(db.String(64), nullable=False)
    ip = db.Column(db.String(64), nullable=True)

    # MAC address — unique endpoint identity
    mac = db.Column(db.String(32), nullable=False, unique=True, index=True)

    # ============================================================
    # 🔹 Status + Telemetry
    # ============================================================
    status = db.Column(db.String(20), default="offline")  # online | offline | quarantined
    last_seen = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))

    # Resource metrics
    cpu_percent = db.Column(db.Float, default=0.0)
    mem_percent = db.Column(db.Float, default=0.0)
    agent_version = db.Column(db.String(32), default="0.1-sim")

    notes = db.Column(db.String(255), default="")
    
    # Risk & Priority
    risk_level = db.Column(db.String(20), default="low")  # low, medium, high, critical
    priority = db.Column(db.Integer, default=0)           # 0=Normal, 1=High, 2=Critical

    # ============================================================
    # 🔹 Relationships
    # ============================================================
    organization = db.relationship("Organization", back_populates="devices")

    telemetry = db.relationship(
        "DeviceTelemetry",
        back_populates="device",
        lazy=True,
        cascade="all, delete-orphan"
    )

    events = db.relationship("Event", back_populates="device", cascade="all, delete-orphan")


    # ============================================================
    # 🔹 Methods
    # ============================================================
    def mark_seen(self, cpu=None, mem=None):
        """Update heartbeat timestamp and optional resource metrics."""
        self.last_seen = datetime.now(timezone.utc)
        self.status = "online"
        if cpu is not None:
            self.cpu_percent = cpu
        if mem is not None:
            self.mem_percent = mem
        db.session.commit()

    def mark_offline(self):
        """Mark the device offline after missed heartbeats."""
        self.status = "offline"
        db.session.commit()

    def as_dict(self):
        """Compact JSON-safe device representation."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "name": self.device_name,
            "os": self.os,
            "ip": self.ip,
            "mac": self.mac,
            "status": self.status,
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S UTC") if self.last_seen else None,
            "cpu": round(self.cpu_percent, 2),
            "mem": round(self.mem_percent, 2),
            "agent_version": self.agent_version,
            "notes": self.notes,
        }

    def __repr__(self):
        return f"<Device {self.device_name} ({self.mac}) - {self.status}>"

    # ============================================================
    # 🔹 Compatibility Properties (for Dashboard)
    # ============================================================
    @property
    def hostname(self):
        return self.device_name

    @property
    def ip_address(self):
        return self.ip
