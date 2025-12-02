from flask_mail import Message
from app.extensions import mail
from flask import current_app
from twilio.rest import Client

def send_email_alert(to_email, subject, body):
    """Send an alert email."""
    try:
        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
        return True
    except Exception as e:
        current_app.logger.error(f"[EMAIL ALERT FAILED] {e}")
        return False


def send_sms_alert(to_phone, body):
    """Send an SMS alert using Twilio."""
    try:
        account_sid = current_app.config["TWILIO_ACCOUNT_SID"]
        auth_token = current_app.config["TWILIO_AUTH_TOKEN"]
        from_number = current_app.config["TWILIO_FROM_NUMBER"]

        client = Client(account_sid, auth_token)
        client.messages.create(to=to_phone, from_=from_number, body=body)
        return True
    except Exception as e:
        current_app.logger.error(f"[SMS ALERT FAILED] {e}")
        return False
