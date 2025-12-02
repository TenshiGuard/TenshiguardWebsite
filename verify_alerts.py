from app import create_app
from app.models.event import Event
from app.extensions import db
from sqlalchemy import desc

def verify_alerts():
    app = create_app()
    with app.app_context():
        print("\n--- Verifying Correlation Alerts ---")
        
        # Fetch recent correlation events
        alerts = Event.query.filter_by(event_type="correlation").order_by(desc(Event.ts)).limit(10).all()
        
        if not alerts:
            print("No correlation alerts found.")
            return

        for alert in alerts:
            print(f"[{alert.ts}] {alert.severity.upper()} - {alert.message}")
            print(f"    Category: {alert.category}")
            print(f"    Detail: {alert.detail}")
            print("-" * 50)

if __name__ == "__main__":
    verify_alerts()
