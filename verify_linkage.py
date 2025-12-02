from app import create_app, db
from app.models import User, Organization, Event

app = create_app()

with app.app_context():
    print("--- User & Organization Linkage ---")
    user = User.query.filter_by(email="admin@tenshiguard.com").first()
    if not user:
        print("CRITICAL: User 'admin@tenshiguard.com' not found!")
    else:
        print(f"User: {user.username} (ID: {user.id})")
        print(f"User Org ID: {user.organization_id}")
        
        org = Organization.query.get(user.organization_id)
        if not org:
            print(f"CRITICAL: Organization ID {user.organization_id} not found!")
        else:
            print(f"Organization: {org.name} (ID: {org.id})")
            print(f"Org Token: {org.agent_token}")

            print("\n--- Event Check for THIS Organization ---")
            # Check for ANY events
            total_events = Event.query.filter_by(organization_id=org.id).count()
            print(f"Total Events for Org {org.id}: {total_events}")

            # Check for High/Critical events
            high_events = Event.query.filter_by(organization_id=org.id).filter(Event.severity.in_(["high", "critical"])).count()
            print(f"High/Critical Events for Org {org.id}: {high_events}")

            if high_events > 0:
                latest = Event.query.filter_by(organization_id=org.id).filter(Event.severity.in_(["high", "critical"])).order_by(Event.ts.desc()).first()
                print(f"Latest High/Critical Event: ID {latest.id} | {latest.message} | {latest.ts}")
            else:
                print("WARNING: No high/critical events found for this organization.")

            print("\n--- Check for Orphaned Events ---")
            orphans = Event.query.filter(Event.organization_id != org.id).count()
            print(f"Events belonging to OTHER organizations: {orphans}")
