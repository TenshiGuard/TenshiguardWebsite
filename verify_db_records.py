from app import create_app, db
from app.models import Event, AISignal, Organization, Device

app = create_app()

with app.app_context():
    print("--- Organization Info ---")
    org = Organization.query.first()
    if org:
        print(f"Org: {org.name} (ID: {org.id})")
        print(f"Token: {org.agent_token}")
    else:
        print("No Organization found!")

    print("\n--- Searching for Ransomware Event ---")
    ransom_event = Event.query.filter(Event.message.ilike("%Ransomware%")).first()
    if ransom_event:
        print(f"FOUND: ID: {ransom_event.id} | Sev: {ransom_event.severity} | Msg: {ransom_event.message}")
    else:
        print("NOT FOUND: No event with 'Ransomware' in message.")

    print("\n--- High/Critical Events ---")
    high_events = Event.query.filter(Event.severity.in_(["high", "critical"])).all()
    if not high_events:
        print("No High/Critical events found.")
    for e in high_events:
        print(f"ID: {e.id} | Type: {e.category} | Sev: {e.severity} | Msg: {e.message}")
