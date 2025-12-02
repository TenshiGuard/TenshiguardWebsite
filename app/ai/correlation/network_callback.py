from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models.event import Event
from app.models.ai_signal import AISignal


class NetworkCallbackDetector:

    WINDOW = 180   # 3 minutes

    def handle(self, event: Event):
        if event.category != "network":
            return

        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=self.WINDOW)

        recent = (
            Event.query
            .filter(Event.device_id == event.device_id)
            .filter(Event.category == "network")
            .filter(Event.dest_ip == event.dest_ip)
            .filter(Event.ts >= start)
            .all()
        )

        if len(recent) >= 4:
            self._raise(event, "high", f"Repeated callback to IP {event.dest_ip}")

    def _raise(self, event, severity, detail):
        signal = AISignal(
            organization_id=event.organization_id,
            device_id=event.device_id,
            mac=event.mac,
            category="network",
            severity=severity,
            rule_name="C2 Callback Pattern",
            detail=detail,
            risk_score=75,
            mitigation="Block outbound traffic to the destination and inspect running processes",
        )
        db.session.add(signal)
        db.session.commit()
