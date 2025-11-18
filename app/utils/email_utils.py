"""Helpers for sending transactional email in a provider-agnostic way."""
from __future__ import annotations

import json
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Optional

import requests
from fastapi import BackgroundTasks
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def _email_from() -> str:
    sender = os.getenv("EMAIL_FROM")
    if not sender:
        raise RuntimeError("EMAIL_FROM must be configured")
    return sender


def _provider() -> str:
    return os.getenv("EMAIL_PROVIDER", "smtp").lower()


def _validate_provider(provider: str) -> None:
    if provider == "smtp":
        for key in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_PASSWORD"):
            if not os.getenv(key):
                raise RuntimeError(
                    f"{key} is required for SMTP email delivery")
        # Port defaults to 465 if not provided
        os.getenv("SMTP_PORT", "465")
    elif provider == "sendgrid":
        if not os.getenv("SENDGRID_API_KEY"):
            raise RuntimeError(
                "SENDGRID_API_KEY is required for SendGrid delivery")
    elif provider == "console":
        # no configuration required
        pass
    else:
        raise RuntimeError(f"Unsupported EMAIL_PROVIDER '{provider}'")


def _send_via_smtp(subject: str, to_email: str, body: str) -> None:
    host = os.environ["SMTP_HOST"]
    username = os.environ["SMTP_USERNAME"]
    password = os.environ["SMTP_PASSWORD"]
    port = int(os.getenv("SMTP_PORT", "465"))

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = _email_from()
    msg["To"] = to_email
    msg.set_content(body)

    with smtplib.SMTP_SSL(host, port) as smtp:
        smtp.login(username, password)
        smtp.send_message(msg)


def _send_via_sendgrid(subject: str, to_email: str, body: str) -> None:
    api_key = os.environ["SENDGRID_API_KEY"]
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": _email_from()},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }
    response = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        data=json.dumps(payload),
        timeout=10,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"SendGrid failed with status {
                response.status_code}: {
                response.text}")


def _send_email(subject: str, to_email: str, body: str) -> None:
    provider = _provider()
    _validate_provider(provider)
    if provider == "smtp":
        _send_via_smtp(subject, to_email, body)
    elif provider == "sendgrid":
        _send_via_sendgrid(subject, to_email, body)
    else:
        logger.info("Email to %s: %s", to_email, body)


def _dispatch(subject: str, to_email: str, body: str,
              background_tasks: Optional[BackgroundTasks]) -> None:
    # Validate configuration before scheduling background work to fail fast
    _validate_provider(_provider())
    if background_tasks:
        background_tasks.add_task(_send_email, subject, to_email, body)
    else:
        _send_email(subject, to_email, body)


def send_verification_email(
        to_email: str,
        token: str,
        background_tasks: Optional[BackgroundTasks] = None) -> None:
    link = f"http://localhost:8000/verify-email?token={token}"
    subject = "Verify Your SecureVault Account"
    body = (
        "Please verify your email by clicking the following link:"
        f"\n\n{link}"
    )
    _dispatch(subject, to_email, body, background_tasks)


def send_password_reset_email(
        to_email: str,
        link: str,
        background_tasks: Optional[BackgroundTasks] = None) -> None:
    subject = "SecureVault password reset"
    body = f"Click the following link to reset your password:\n\n{link}"
    _dispatch(subject, to_email, body, background_tasks)
