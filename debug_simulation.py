from app import create_app
from app.models.event import Event
from app.models.ai_signal import AISignal
from app.extensions import db
from sqlalchemy import desc

def debug_events():
    app = create_app()
    with app.app_context():
        print("\n--- Debugging Ransomware Events ---")
        # Check for file events
        file_events = Event.query.filter_by(category="file").order_by(desc(Event.ts)).limit(5).all()
        for e in file_events:
            print(f"Event ID: {e.id} | Type: {e.event_type} | Detail: {e.detail}")

        print("\n--- Debugging Lateral Movement Events ---")
        # Check for auth events from the attacker IP
        attacker_ip = "192.168.1.200"
        auth_events = Event.query.filter_by(source_ip=attacker_ip).all()
        print(f"Found {len(auth_events)} events from {attacker_ip}")
        for e in auth_events:
            print(f"Event ID: {e.id} | Device ID: {e.device_id} | IP: {e.source_ip}")

        print("\n--- Debugging AI Signals ---")
        signals = AISignal.query.order_by(desc(AISignal.ts)).limit(10).all()
        for s in signals:
             print(f"Signal ID: {s.id} | Category: {s.category} | Rule: {s.rule_name} | Detail: {s.detail}")

if __name__ == "__main__":
    debug_events()
