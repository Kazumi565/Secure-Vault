"""Test email verification flow with FRONTEND_BASE_URL."""
import logging


def test_verification_email_uses_frontend_base_url(
    client, monkeypatch, caplog
):
    """Verification email link should use FRONTEND_BASE_URL."""
    monkeypatch.setenv("FRONTEND_BASE_URL", "https://example.com")

    # Ensure we capture INFO level logs from email_utils
    caplog.set_level(logging.INFO, logger="app.utils.email_utils")

    # Register a user
    res = client.post(
        "/register",
        json={
            "email": "verify-test@example.com",
            "password": "Test123!",
            "full_name": "Test User"
        }
    )
    assert res.status_code == 200

    # Check that the email provider logged the message with the correct URL
    # (Since we're using console provider in tests)
    log_output = caplog.text
    # The link should point to the frontend, not the backend
    assert "https://example.com/verify?token=" in log_output
    assert "localhost:8000" not in log_output


def test_verify_email_redirects_to_frontend_base_url(client, monkeypatch):
    """Verify email endpoint should redirect to FRONTEND_BASE_URL."""
    monkeypatch.setenv("FRONTEND_BASE_URL", "https://example.com")

    # Register a user first
    res = client.post(
        "/register",
        json={
            "email": "redirect-test@example.com",
            "password": "Test123!",
            "full_name": "Test User"
        }
    )
    assert res.status_code == 200

    # Get the user's verification token from the database
    from app.database import SessionLocal
    from app.models import User
    db = SessionLocal()
    user = db.query(User).filter(
        User.email == "redirect-test@example.com"
    ).first()
    token = user.verification_token
    db.close()

    # Verify with valid token
    res = client.get(f"/verify-email?token={token}", follow_redirects=False)
    assert res.status_code == 307  # Redirect
    loc = "https://example.com/verified?success=true"
    assert res.headers["location"] == loc

    # Verify with invalid token
    res = client.get("/verify-email?token=invalid", follow_redirects=False)
    assert res.status_code == 307  # Redirect
    loc = "https://example.com/verified?success=false"
    assert res.headers["location"] == loc
