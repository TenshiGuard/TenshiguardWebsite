# =========================================================
# app/utils/notify.py
# TenshiGuard Notification Utility (Email + SMS)
# =========================================================

import os
from flask import current_app
from flask_mail import Message
from app.extensions import mail
from twilio.rest import Client


# =========================================================
# 🔹 EMAIL ALERTS — Gmail via Flask-Mail
# =========================================================
def send_email_alert(to_email: str, subject: str, body: str) -> bool:
    """Send an alert email using Flask-Mail and Gmail App Password."""
    try:
        # Ensure required configs exist
        username = os.getenv("MAIL_USERNAME")
        if not username:
            raise ValueError("MAIL_USERNAME not found in environment")

        with mail.connect() as conn:
            msg = Message(
                subject=subject,
                sender=os.getenv("DEFAULT_FROM_EMAIL", username),
                recipients=[to_email],
                body=body
            )
            conn.send(msg)

        current_app.logger.info(f"✅ Email sent successfully to {to_email}")
        print(f"✅ Email sent successfully to {to_email}")
        return True

    except Exception as e:
        current_app.logger.error(f"❌ Email send failed: {e}")
        print(f"❌ Email send failed: {e}")
        return False


# =========================================================
# 🔹 SMS ALERTS — Twilio API
# =========================================================
def send_sms_alert(to_number: str, body: str) -> bool:
    """Send an SMS alert via Twilio API (with safe fallbacks)."""
    try:
        account_sid = os.getenv("TWILIO_ACCOUNT_SID")
        auth_token = os.getenv("TWILIO_AUTH_TOKEN")
        from_number = os.getenv("TWILIO_FROM_NUMBER")

        # Handle missing credentials safely
        if not all([account_sid, auth_token, from_number]):
            current_app.logger.warning("⚠️ Twilio credentials missing. Skipping SMS.")
            print("⚠️ Twilio credentials missing. Skipping SMS.")
            return False

        client = Client(account_sid, auth_token)
        message = client.messages.create(
            body=body,
            from_=from_number,
            to=to_number
        )

        current_app.logger.info(f"✅ SMS sent to {to_number} | SID: {message.sid}")
        print(f"✅ SMS sent to {to_number} | SID: {message.sid}")
        return True

    except Exception as e:
        current_app.logger.error(f"❌ SMS send failed: {e}")
        print(f"❌ SMS send failed: {e}")
        return False
