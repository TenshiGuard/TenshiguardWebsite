from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models.event import Event
from app.models.ai_signal import AISignal


class BruteForceDetector:

    WINDOW = 60            # seconds
    THRESH_HIGH = 5
    THRESH_CRITICAL = 10

    def handle(self, event: Event):
        if event.action != "failed_login":
            return

        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=self.WINDOW)

        recent = (
            Event.query
            .filter(Event.organization_id == event.organization_id)
            .filter(Event.action == "failed_login")
            .filter(Event.ts >= start)
            .all()
        )

        count = len(recent)
        src_ip = event.detail or event.source_ip if hasattr(event, "source_ip") else None

        if count >= self.THRESH_CRITICAL:
            self._raise(event, count, "critical", "Repeated failed logins detected")
        elif count >= self.THRESH_HIGH:
            self._raise(event, count, "high", "Multiple failed logins detected")

    def _raise(self, event, count, severity, msg):
        signal = AISignal(
            organization_id=event.organization_id,
            device_id=event.device_id,
            mac=event.mac,
            category="auth",
            severity=severity,
            rule_name="Brute Force Pattern",
            detail=f"{count} failed logins in last 60s",
            risk_score=80 if severity == "critical" else 60,
            mitigation="Block source IP, enforce MFA",
            raw={"count": count},
        )
        db.session.add(signal)
        db.session.commit()
