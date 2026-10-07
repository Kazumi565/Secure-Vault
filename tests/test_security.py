import re

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import Account, ActionToken, LoginSession, now
from tests.conftest import PASSWORD, create_user, upload


def test_session_cookie_csrf_and_origin(app, user):
    response = user.get("/api/auth/session")
    assert response.status_code == 200
    assert "vault_session" in user.cookies
    bad = user.patch("/api/auth/profile", json={"full_name": "Changed"}, headers={"X-CSRF-Token": "wrong"})
    assert bad.status_code == 403
    assert (
        user.patch(
            "/api/auth/profile", json={"full_name": "Changed"}, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    assert user.patch("/api/auth/profile", json={"full_name": "Changed"}).status_code == 200
    assert user.get("/api/auth/session").headers["cache-control"] == "no-store"
    login = user.post("/api/auth/login", json={"email": "person@example.com", "password": PASSWORD})
    cookie = login.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/api" in cookie
    with app.state.sessions() as db:
        assert all(s.token_hash != user.cookies["vault_session"] for s in db.scalars(select(LoginSession)))


def test_unverified_cannot_use_file_api(app):
    user = create_user(app, verified=False)
    assert upload(user).status_code == 403
    assert user.get("/api/files").status_code == 403
    assert user.get("/api/storage").status_code == 403
    assert user.post("/api/auth/resend-verification").status_code == 200


def test_cross_user_access_and_admin_denial(app, user):
    other = create_user(app, "other@example.com")
    fid = upload(user).json()["id"]
    for method, path, payload in [
        ("get", f"/api/files/{fid}/download", None),
        ("delete", f"/api/files/{fid}", None),
        ("get", f"/api/files/{fid}/versions", None),
        ("post", f"/api/files/{fid}/shares", {}),
    ]:
        kwargs = {"json": payload} if payload is not None else {}
        assert getattr(other, method)(path, **kwargs).status_code == 404
    assert user.get("/api/admin/users").status_code == 403
    assert user.delete(f"/api/admin/files/{fid}").status_code == 403
    assert TestClient(app).get("/api/files").status_code == 401


def test_password_change_revokes_every_session(app, user):
    second = TestClient(app)
    assert second.post("/api/auth/login", json={"email": "person@example.com", "password": PASSWORD}).status_code == 200
    result = user.post("/api/auth/password", json={"password": PASSWORD, "new_password": "AnotherStrongPassword456!"})
    assert result.status_code == 200
    assert user.get("/api/auth/session").status_code == 401
    assert second.get("/api/auth/session").status_code == 401


def test_password_reset_hashes_tokens_and_is_single_use(app, user):
    user.post("/api/auth/forgot-password", json={"email": "person@example.com"})
    message = next(m for m in reversed(app.state.sent_mail) if m["subject"] == "Reset your password")
    token = re.search(r"token=([\w-]+)", message["body"]).group(1)
    with app.state.sessions() as db:
        record = db.scalar(select(ActionToken).where(ActionToken.purpose == "reset"))
        assert record.token_hash != token
    data = {"token": token, "new_password": "NewPasswordWithLength123!"}
    assert user.post("/api/auth/reset-password", json=data).status_code == 200
    assert user.post("/api/auth/reset-password", json=data).status_code == 400
    assert user.get("/api/auth/session").status_code == 401


def test_login_rate_limit_and_validation_redaction(app, client):
    app.state.settings.login_limit = 2
    for _ in range(2):
        assert (
            client.post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}).status_code
            == 401
        )
    assert client.post("/api/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}).status_code == 429
    response = client.post("/api/auth/register", json={"email": "bad", "password": "secret"})
    assert response.status_code == 422
    assert "secret" not in response.text


def test_totp_and_single_use_recovery_codes(app, user):
    result = user.post("/api/auth/2fa/setup", json={"password": PASSWORD})
    assert result.status_code == 200
    code = pyotp.TOTP(result.json()["secret"]).now()
    enabled = user.post("/api/auth/2fa/enable", json={"code": code})
    assert enabled.status_code == 200
    recovery = enabled.json()["recovery_codes"][0]
    fresh = TestClient(app)
    data = {"email": "person@example.com", "password": PASSWORD}
    assert fresh.post("/api/auth/login", json=data).status_code == 401
    assert fresh.post("/api/auth/login", json=data | {"code": recovery}).status_code == 200
    assert fresh.post("/api/auth/login", json=data | {"code": recovery}).status_code == 401
    with app.state.sessions() as db:
        account = db.scalar(select(Account))
        assert result.json()["secret"] not in account.totp_secret


def test_expired_session_rejected(app, user):
    with app.state.sessions.begin() as db:
        for session in db.scalars(select(LoginSession)):
            session.expires_at = now()
    assert user.get("/api/auth/session").status_code == 401


def test_avatar_validation(app, user):
    assert user.post("/api/auth/avatar", files={"file": ("fake.png", b"not an image", "image/png")}).status_code == 400
    assert user.post("/api/auth/avatar", files={"file": ("big.png", b"x" * (2 * 1024 * 1024 + 1))}).status_code == 413


def test_login_cannot_create_session_after_concurrent_password_reset(app, user, monkeypatch):
    from app import auth
    from app.security import hash_password

    original = auth.locked_user

    def reset_before_lock(db, user_id):
        with app.state.sessions.begin() as other:
            other.get(Account, user_id).hashed_password = hash_password("ConcurrentResetPassword123!")
        return original(db, user_id)

    monkeypatch.setattr(auth, "locked_user", reset_before_lock)
    response = TestClient(app).post("/api/auth/login", json={"email": "person@example.com", "password": PASSWORD})
    assert response.status_code == 401


def test_stale_admin_cannot_demote_last_administrator(app, user, monkeypatch):
    from app import activity

    other = create_user(app, "second@example.com")
    with app.state.sessions.begin() as db:
        accounts = db.scalars(select(Account)).all()
        for account in accounts:
            account.role = "admin"
        first_id, second_id = [a.id for a in accounts]
    original = activity.lock_administrators

    def demote_before_lock(db):
        with app.state.sessions.begin() as parallel:
            parallel.get(Account, first_id).role = "user"
        return original(db)

    monkeypatch.setattr(activity, "lock_administrators", demote_before_lock)
    response = user.patch(f"/api/admin/users/{second_id}/role", json={"role": "user"})
    assert response.status_code == 403
    assert other.get("/api/admin/users").status_code == 200
