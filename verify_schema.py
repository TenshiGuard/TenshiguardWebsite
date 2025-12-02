from app import create_app, db
from app.models.event import Event
from sqlalchemy import inspect

app = create_app()

with app.app_context():
    inspector = inspect(db.engine)
    columns = [c['name'] for c in inspector.get_columns('event')]
    
    print(f"Columns in 'event' table: {columns}")
    
    if 'mitigation' in columns:
        print("SUCCESS: 'mitigation' column found in database.")
    else:
        print("FAILURE: 'mitigation' column MISSING in database.")
        
    # Check model attribute
    if hasattr(Event, 'mitigation'):
        print("SUCCESS: 'mitigation' attribute found in Event model.")
    else:
        print("FAILURE: 'mitigation' attribute MISSING in Event model.")
