import json
from app import create_app
from app.models import Organization, Device, Event, AISignal
from app.extensions import db
from app.ai.services.ai_engine import AIEngine
from app.ai.services.correlation_engine import CorrelationEngine

def verify_logic():
    app = create_app()
    with app.app_context():
        print("--- Initializing Engines ---")
        ai_engine = AIEngine(app)
        corr_engine = CorrelationEngine(app)
        
        # Setup Test Data
        org = Organization.query.first()
        if not org:
            print("No org found")
            return

        print(f"Using Org: {org.name}")
        
        # 1. Test Ransomware Logic
        print("\n--- Testing Ransomware Logic ---")
        # Create a dummy device
        dev = Device.query.first()
        
        payload = {
            "type": "file",
            "file_name": "test_ransom.docx.enc",
            "path": "C:\\Data\\test_ransom.docx.enc",
            "file_hash": "a" * 64,
            "hostname": "test-host",
            "mac": "00:00:00:00:00:00",
            "ip": "1.2.3.4"
        }
        
        # AI Engine Analysis
        signal_data = ai_engine.analyze(payload)
        if signal_data:
            print(f"[AI Match] Rule: {signal_data['rule_name']} | Detail: {signal_data['detail']}")
            
            # Save Signal (mocking API behavior)
            signal_row = AISignal(
                organization_id=org.id,
                device_id=dev.id,
                category=signal_data["category"],
                severity=signal_data["severity"],
                rule_name=signal_data["rule_name"],
                detail=signal_data["detail"], # Using the fixed logic
                risk_score=signal_data["risk_score"],
                raw=payload
            )
            db.session.add(signal_row)
            db.session.commit()
            
            # Correlation
            alerts = corr_engine.process(org, dev, signal_row, payload)
            for alert in alerts:
                print(f"[Correlation Alert] {alert['rule_name']} - {alert['detail']}")
        else:
            print("[AI Match] None")

        # 2. Test Lateral Movement Logic
        print("\n--- Testing Lateral Movement Logic ---")
        attacker_ip = "10.10.10.10"
        
        # Create 3 events from same IP to different devices (mocking DB events)
        # We need distinct device IDs.
        devices = Device.query.limit(3).all()
        if len(devices) < 2:
            print("Not enough devices for lateral movement test")
        else:
            # Clear old events for clean test? No, just add new ones.
            for d in devices:
                e = Event(
                    organization_id=org.id,
                    device_id=d.id,
                    event_type="auth",
                    category="auth",
                    severity="medium",
                    source_ip=attacker_ip, # Using the new column
                    detail="Failed login",
                    ts=db.func.now()
                )
                db.session.add(e)
            db.session.commit()
            
            # Now trigger the rule with a new signal
            last_dev = devices[0]
            signal_row_lat = AISignal(
                organization_id=org.id,
                device_id=last_dev.id,
                category="auth",
                severity="medium",
                rule_name="Failed login attempt",
                detail="Failed login",
                risk_score=50,
                raw={"source_ip": attacker_ip}
            )
            
            alerts = corr_engine.process(org, last_dev, signal_row_lat, {"source_ip": attacker_ip})
            for alert in alerts:
                print(f"[Correlation Alert] {alert['rule_name']} - {alert['detail']}")

if __name__ == "__main__":
    verify_logic()
