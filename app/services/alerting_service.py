from __future__ import annotations
from datetime import datetime, time
from typing import Optional

from flask import current_app
from app.models import AlertPreference, Alert, Organization
from app.extensions import db
from app.utils.notify import send_email_alert, send_sms_alert

def _within_off_hours(pref: AlertPreference, now: Optional[datetime] = None) -> bool:
    """
    Returns True if 'now' is within off-hours window OR the pref says always_on.
    If start > end, treats it as overnight (e.g., 20:00 -> 07:00 next day).
    """
    if pref.always_on:
        return True

    now = now or datetime.utcnow()
    start = time(pref.off_start_hour or 0, 0)
    end = time(pref.off_end_hour or 0, 0)
    cur = now.time()

    if start <= end:
        return start <= cur < end
    else:
        # overnight window
        return cur >= start or cur < end

def _meets_severity(min_required: str, incoming: str) -> bool:
    order = ["info", "low", "medium", "high", "critical"]
    try:
        return order.index(incoming) >= order.index(min_required)
    except ValueError:
        return False

def maybe_send_alert(org: Organization, title: str, message: str, severity: str = "medium", category: str = "security") -> Alert:
    """
    Apply AlertPreference gatekeeping; persist Alert; send notifications as configured.
    """
    # 1) Load prefs (if none, create sane defaults)
    pref: AlertPreference = AlertPreference.query.filter_by(organization_id=org.id).first()
    if not pref:
        pref = AlertPreference(
            organization_id=org.id,
            email_enabled=True,
            sms_enabled=False,
            min_severity="high",
            always_on=False,
            off_start_hour=19,
            off_end_hour=8,
        )
        db.session.add(pref)
        db.session.commit()

    # 2) Check severity + off-hours
    should_notify = True
    if not _meets_severity(pref.min_severity or "high", severity):
        should_notify = False
    elif not _within_off_hours(pref):
        should_notify = False

    # 3) Create alert
    alert = Alert(
        organization_id=org.id,
        title=title,
        message=message,
        severity=severity,
        category=category,
        sent_email=False,
        sent_sms=False,
    )
    db.session.add(alert)
    db.session.commit()

    if not should_notify:
        return alert

    # 4) Deliver email
    if pref.email_enabled and pref.email_to:
        subject = f"[TenshiGuard SOS • {severity.upper()}] {title}"
        if send_email_alert(pref.email_to, subject, message):
            alert.sent_email = True

    # 5) Deliver SMS
    if pref.sms_enabled and pref.sms_to:
        sms_body = f"{severity.upper()} | {title}: {message}"
        if send_sms_alert(pref.sms_to, sms_body):
            alert.sent_sms = True

    db.session.commit()
    return alert
