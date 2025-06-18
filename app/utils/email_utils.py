import os
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

EMAIL_FROM = os.getenv("EMAIL_FROM")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")


def send_verification_email(to_email: str, link: str):
    msg = EmailMessage()
    msg["Subject"] = "Verify your SecureVault account"
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Click the following link to verify your account:\n\n{link}")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_FROM, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("✅ Verification email sent")
    except Exception as e:
        print("❌ Failed to send verification email:", e)


def send_password_reset_email(to_email: str, link: str):
    msg = EmailMessage()
    msg["Subject"] = "Reset your SecureVault password"
    msg["From"] = EMAIL_FROM
    msg["To"] = to_email
    msg.set_content(f"Click the following link to reset your password:\n\n{link}")

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_FROM, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print("✅ Password reset email sent")
    except Exception as e:
        print("❌ Failed to send reset email:", e)
