
import random
from datetime import datetime, timedelta, timezone
from app import create_app, db
from app.models import Organization, Device, Alert, Event
from app.models.device_telemetry import DeviceTelemetry

app = create_app()

def seed_data():
    with app.app_context():
        print("Seeding Dashboard Data...")

        # 1. Get Organization
        org = Organization.query.first()
        if not org:
            print("No organization found. Please register first.")
            return

        print(f"Using Organization: {org.name}")

        # 2. Seed Devices (OS Distribution)
        os_types = [
            ("Windows 11", "windows"),
            ("Ubuntu 22.04", "linux"),
            ("macOS Sonoma", "macos"),
            ("Debian 12", "linux"),
            ("Windows Server 2022", "windows")
        ]

        devices = []
        for name, os_key in os_types:
            mac = f"00:00:00:00:00:{random.randint(10, 99)}"
            dev = Device.query.filter_by(mac=mac).first()
            if not dev:
                dev = Device(
                    organization_id=org.id,
                    device_name=f"Seed-{name.split()[0]}",
                    mac=mac,
                    os=name,
                    ip=f"192.168.1.{random.randint(100, 200)}",
                    status="online",
                    last_seen=datetime.now(timezone.utc)
                )
                db.session.add(dev)
                print(f"   Created Device: {dev.device_name} ({dev.os})")
            else:
                print(f"   Device exists: {dev.device_name}")
            devices.append(dev)
        
        db.session.commit()

        # 3. Seed Alerts (Severity Distribution)
        severities = ["critical", "high", "medium", "low", "info"]
        for sev in severities:
            # Create a few alerts for each severity
            for i in range(random.randint(2, 5)):
                alert = Alert(
                    organization_id=org.id,
                    title=f"Sample {sev.upper()} Alert {i}",
                    message=f"This is a simulated {sev} severity event.",
                    severity=sev,
                    category="security",
                    created_at=datetime.now(timezone.utc) - timedelta(minutes=random.randint(1, 60))
                )
                db.session.add(alert)
        print(f"   Seeded random severity alerts.")

        # 4. Seed Failed Logins (Trend)
        # Needs: category='auth'/'security', title/message contains 'fail'
        # Spread over last 24 hours
        now = datetime.now(timezone.utc)
        for i in range(20):
            hours_ago = random.randint(0, 23)
            ts = now - timedelta(hours=hours_ago)
            
            alert = Alert(
                organization_id=org.id,
                title="Failed Login Attempt",
                message=f"Failed login detected from IP 10.0.0.{random.randint(1, 255)}",
                severity="high",
                category="auth",
                created_at=ts
            )
            db.session.add(alert)
        print(f"   Seeded failed login alerts over last 24h.")

        # 5. Seed Telemetry (Performance Trend)
        # Add some historical data for the new devices
        for dev in devices:
            for i in range(24): # Last 24 hours
                ts = now - timedelta(hours=i)
                telemetry = DeviceTelemetry(
                    device_id=dev.id,
                    cpu_percent=random.uniform(10, 90),
                    mem_percent=random.uniform(20, 80),
                    agent_version="1.0.0",
                    ts=ts
                )
                db.session.add(telemetry)
        print(f"   Seeded historical telemetry.")

        db.session.commit()
        print("Seeding Complete!")

if __name__ == "__main__":
    seed_data()
