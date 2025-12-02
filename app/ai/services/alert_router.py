from app.services.alerts import raise_alert

class AIAlertRouter:

    def route(self, ai_event):
        if ai_event.threat_level == "high":
            raise_alert(
                org_id=None, 
                device_id=ai_event.device_id,
                title="High Threat Detected",
                message=ai_event.summary,
                severity="critical"
            )
        return True
