from flask import Flask, render_template_string
from app import create_app
from app.models import Event, User
from sqlalchemy.orm import joinedload

def verify_render():
    app = create_app()
    with app.app_context():
        # Get Admin User & Org
        user = User.query.filter_by(email="admin@tenshiguard.com").first()
        org = user.organization
        
        # Fetch Alerts (Same query as route)
        alerts = (
            Event.query.options(joinedload(Event.device))
            .filter_by(organization_id=org.id)
            .filter(Event.severity.in_(["high", "critical"]))
            .order_by(Event.ts.desc())
            .limit(10)
            .all()
        )
        
        print(f"Found {len(alerts)} alerts for rendering.")
        
        # Mini Template
        template = """
        {% for alert in alerts %}
          ROW: {{ alert.ts }} | {{ alert.category }} | {{ alert.message }}
        {% endfor %}
        """
        
        rendered = render_template_string(template, alerts=alerts)
        print("--- Rendered Output ---")
        print(rendered)

if __name__ == "__main__":
    verify_render()
