import json
import logging
import smtplib
import ssl
from datetime import timedelta
from email.message import EmailMessage

from sqlalchemy import select

from app.models import MailMessage, now

logger = logging.getLogger(__name__)


def enqueue(db, app, recipient, subject, body):
    payload = json.dumps({"to": recipient, "subject": subject, "body": body}).encode()
    db.add(MailMessage(encrypted_payload=app.state.crypto.wrap(payload)))


def flush_mail(app, limit=20):
    settings = app.state.settings
    for _ in range(limit):
        with app.state.sessions() as db:
            message = db.scalar(
                select(MailMessage)
                .where(MailMessage.available_at <= now())
                .order_by(MailMessage.created_at)
                .with_for_update(skip_locked=True)
                .limit(1)
            )
            if not message:
                break
            message.attempts += 1
            message.available_at = now() + timedelta(minutes=min(60, 2 ** min(message.attempts, 6)))
            payload = json.loads(app.state.crypto.unwrap(message.encrypted_payload))
            try:
                if settings.testing:
                    app.state.sent_mail.append(payload)
                elif settings.email_provider == "console":
                    # Deliberately local-only delivery. Production rejects this provider.
                    print(f"Development email to {payload['to']}: {payload['subject']}\n{payload['body']}")
                else:
                    mail = EmailMessage()
                    mail["From"] = settings.email_from
                    mail["To"] = payload["to"]
                    mail["Subject"] = payload["subject"]
                    mail.set_content(payload["body"])
                    transport = smtplib.SMTP_SSL if settings.smtp_ssl else smtplib.SMTP
                    tls = ssl.create_default_context()
                    options = {"context": tls} if settings.smtp_ssl else {}
                    with transport(settings.smtp_host, settings.smtp_port, timeout=15, **options) as smtp:
                        if settings.smtp_tls and not settings.smtp_ssl:
                            smtp.starttls(context=tls)
                        if settings.smtp_username:
                            smtp.login(settings.smtp_username, settings.smtp_password)
                        smtp.send_message(mail)
                db.delete(message)
            except Exception:
                # Credentials, addresses, reset links, and provider messages stay out of logs.
                logger.warning("Email delivery deferred for retry")
            db.commit()
