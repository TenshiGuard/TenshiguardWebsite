from datetime import datetime, timedelta, timezone
from app.extensions import db
from app.models.event import Event
from app.models.ai_signal import AISignal


class FileProcessChain:

    WINDOW = 120   # 2 minutes chain window

    def handle(self, event: Event):
        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=self.WINDOW)

        # --- File created? ---
        if event.category == "file":
            return   # file event handled on its own; we need sequences

        # 1) detect file → process sequence
        file_evt = (
            Event.query
            .filter(Event.device_id == event.device_id)
            .filter(Event.category == "file")
            .filter(Event.ts >= start)
            .first()
        )

        if file_evt and event.category == "process":
            self._raise(event, "medium", "Suspicious File → Process Sequence")

        # 2) detect file → process → network callback
        net_evt = (
            Event.query
            .filter(Event.device_id == event.device_id)
            .filter(Event.category == "network")
            .filter(Event.ts >= start)
            .first()
        )

        if file_evt and net_evt:
            self._raise(event, "high", "Suspicious File → Process → Network Callback")

    def _raise(self, event, severity, msg):
        signal = AISignal(
            organization_id=event.organization_id,
            device_id=event.device_id,
            mac=event.mac,
            category="chain",
            severity=severity,
            rule_name="File-Process-Network Chain",
            detail=msg,
            risk_score=70 if severity == "medium" else 90,
            mitigation="Isolate device and inspect executed binaries",
        )
        db.session.add(signal)
        db.session.commit()
