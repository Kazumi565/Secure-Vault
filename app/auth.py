import io
import secrets
from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, Response, UploadFile
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app.dependencies import current_session, current_user, db_session, rate_limit, record, user_json
from app.mail import enqueue, flush_mail
from app.models import Account, ActionToken, FileVersion, LoginSession, StorageGarbage, VaultFile, now
from app.security import digest, hash_password, random_token, verify_password

router = APIRouter(prefix="/auth", tags=["Accounts"])


class EmailInput(BaseModel):
    email: EmailStr


class RegisterInput(EmailInput):
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(default="", max_length=120)


class LoginInput(EmailInput):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(default="", max_length=32)


class PasswordInput(BaseModel):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(default="", max_length=32)


class ResetInput(BaseModel):
    token: str = Field(min_length=20, max_length=100)
    new_password: str = Field(min_length=12, max_length=128)


class ChangePassword(PasswordInput):
    new_password: str = Field(min_length=12, max_length=128)


class ProfileInput(BaseModel):
    full_name: str = Field(max_length=120)

    @field_validator("full_name")
    @classmethod
    def clean_name(cls, value):
        return value.strip()


class CodeInput(BaseModel):
    code: str = Field(min_length=6, max_length=32)


def issue_action(db, request, user, purpose):
    db.execute(delete(ActionToken).where(ActionToken.user_id == user.id, ActionToken.purpose == purpose))
    token = random_token()
    expiry = timedelta(hours=24 if purpose == "verify" else 1)
    db.add(ActionToken(user_id=user.id, purpose=purpose, token_hash=digest(token), expires_at=now() + expiry))
    route = "verify" if purpose == "verify" else "reset-password"
    link = f"{request.app.state.settings.frontend_url.rstrip('/')}/{route}?token={token}"
    enqueue(
        db,
        request.app,
        user.email,
        "Verify your email" if purpose == "verify" else "Reset your password",
        f"Open this link to continue:\n{link}\n\nIgnore this message if you did not request it.",
    )


def check_factor(db, app, user, code):
    if not user.totp_secret:
        return True
    hashes = list(user.recovery_codes or [])
    candidate = digest(code.strip())
    if candidate in hashes:
        hashes.remove(candidate)
        # Account row is locked by the caller for concurrent recovery-code safety.
        user.recovery_codes = hashes
        return True
    totp = pyotp.TOTP(app.state.crypto.unwrap(user.totp_secret).decode())
    step = int(datetime.now(UTC).timestamp()) // 30
    for offset in [-1, 0, 1]:
        matched = step + offset
        if matched > user.last_totp_step and secrets.compare_digest(totp.at(matched * 30), code.strip()):
            result = db.execute(
                update(Account)
                .where(Account.id == user.id, Account.last_totp_step < matched)
                .values(last_totp_step=matched)
            )
            return result.rowcount == 1
    return False


def locked_user(db, user_id):
    # A write first serializes SQLite too; PostgreSQL locks the account row.
    db.execute(update(Account).where(Account.id == user_id).values(used_bytes=Account.used_bytes))
    return db.scalar(
        select(Account).where(Account.id == user_id).with_for_update().execution_options(populate_existing=True)
    )


def require_password(db, request, user, data):
    if not verify_password(data.password, user.hashed_password) or not check_factor(db, request.app, user, data.code):
        raise HTTPException(400, "Incorrect password or authentication code")


@router.post("/register", status_code=201)
def register(data: RegisterInput, request: Request, background: BackgroundTasks, db=Depends(db_session)):
    rate_limit(request, "register", limit=5, seconds=3600)
    email = str(data.email).casefold()
    user = Account(email=email, hashed_password=hash_password(data.password), full_name=data.full_name.strip())
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An account with this email already exists") from None
    issue_action(db, request, user, "verify")
    record(db, user, "account.created")
    db.commit()
    background.add_task(flush_mail, request.app)
    return {"message": "Account created. Check your email to verify it."}


@router.post("/login")
def login(data: LoginInput, request: Request, response: Response, background: BackgroundTasks, db=Depends(db_session)):
    rate_limit(request, "login", str(data.email), limit=request.app.state.settings.login_limit)
    user = db.scalar(select(Account).where(Account.email == str(data.email).casefold()))
    valid = verify_password(data.password, user.hashed_password if user else request.app.state.dummy_hash)
    if not user or not valid:
        raise HTTPException(401, "Incorrect email, password, or authentication code")
    checked_hash = user.hashed_password
    user = locked_user(db, user.id)
    # A password reset may have completed while this request waited for the lock.
    if not user or user.hashed_password != checked_hash:
        raise HTTPException(401, "Incorrect email, password, or authentication code")
    if not check_factor(db, request.app, user, data.code):
        raise HTTPException(401, "Incorrect email, password, or authentication code")
    if user.hashed_password.startswith("$2"):
        user.hashed_password = hash_password(data.password)
    raw = random_token()
    settings = request.app.state.settings
    session = LoginSession(
        token_hash=digest(raw),
        csrf=random_token(),
        user_id=user.id,
        agent=request.headers.get("user-agent", "Unknown browser")[:200],
        expires_at=now() + timedelta(hours=settings.session_hours),
    )
    db.add(session)
    record(db, user, "session.created")
    enqueue(
        db,
        request.app,
        user.email,
        "New sign-in to Secure Vault",
        "A new session was created for your account. If this was not you, reset your password and review your sessions.",
    )
    db.commit()
    response.set_cookie(
        "vault_session",
        raw,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        max_age=settings.session_hours * 3600,
        path="/api",
    )
    background.add_task(flush_mail, request.app)
    return {"user": user_json(user), "csrf_token": session.csrf}


@router.get("/session")
def session_info(user=Depends(current_user), session=Depends(current_session)):
    return {"user": user_json(user), "csrf_token": session.csrf}


@router.post("/logout", status_code=204)
def logout(response: Response, session=Depends(current_session), db=Depends(db_session)):
    db.delete(session)
    db.commit()
    response.delete_cookie("vault_session", path="/api")


@router.post("/verify")
def verify_email(data: dict, request: Request, db=Depends(db_session)):
    rate_limit(request, "verify", limit=20)
    token = data.get("token", "")
    if not isinstance(token, str) or len(token) > 100:
        raise HTTPException(400, "Invalid verification link")
    row = db.scalar(
        select(ActionToken).where(
            ActionToken.token_hash == digest(token), ActionToken.purpose == "verify", ActionToken.expires_at > now()
        )
    )
    if not row:
        raise HTTPException(400, "Invalid or expired verification link")
    user = db.get(Account, row.user_id)
    user.verified = True
    db.delete(row)
    record(db, user, "account.verified")
    db.commit()
    return {"message": "Email verified. You can now use your vault."}


@router.post("/resend-verification")
def resend(request: Request, background: BackgroundTasks, user=Depends(current_user), db=Depends(db_session)):
    rate_limit(request, "resend", user.email, limit=3, seconds=3600)
    if not user.verified:
        issue_action(db, request, user, "verify")
        db.commit()
        background.add_task(flush_mail, request.app)
    return {"message": "A verification email has been queued."}


@router.post("/forgot-password")
def forgot(data: EmailInput, request: Request, background: BackgroundTasks, db=Depends(db_session)):
    rate_limit(request, "forgot", str(data.email), limit=5, seconds=3600)
    user = db.scalar(select(Account).where(Account.email == str(data.email).casefold()))
    if user:
        issue_action(db, request, user, "reset")
        db.commit()
        background.add_task(flush_mail, request.app)
    return {"message": "If that account exists, a reset email has been queued."}


@router.post("/reset-password")
def reset(data: ResetInput, request: Request, db=Depends(db_session)):
    rate_limit(request, "reset", limit=10)
    row = db.scalar(
        select(ActionToken).where(
            ActionToken.token_hash == digest(data.token), ActionToken.purpose == "reset", ActionToken.expires_at > now()
        )
    )
    if not row:
        raise HTTPException(400, "Invalid or expired reset link")
    user = locked_user(db, row.user_id)
    # Claim exactly once, even when two requests submit the same token together.
    claimed = db.execute(delete(ActionToken).where(ActionToken.id == row.id))
    if claimed.rowcount != 1:
        raise HTTPException(400, "Invalid or expired reset link")
    user.hashed_password = hash_password(data.new_password)
    db.execute(delete(ActionToken).where(ActionToken.user_id == user.id))
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    record(db, user, "password.reset")
    db.commit()
    return {"message": "Password reset. Sign in again. Two-factor authentication remains enabled if configured."}


@router.patch("/profile")
def profile(data: ProfileInput, user=Depends(current_user), db=Depends(db_session)):
    user.full_name = data.full_name
    db.commit()
    return user_json(user)


@router.post("/password")
def change_password(
    data: ChangePassword, request: Request, response: Response, user=Depends(current_user), db=Depends(db_session)
):
    rate_limit(request, "sensitive", user.email, limit=10)
    user = locked_user(db, user.id)
    require_password(db, request, user, data)
    user.hashed_password = hash_password(data.new_password)
    db.execute(delete(ActionToken).where(ActionToken.user_id == user.id))
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    record(db, user, "password.changed")
    db.commit()
    response.delete_cookie("vault_session", path="/api")
    return {"message": "Password changed. Sign in again on your devices."}


@router.get("/sessions")
def sessions(user=Depends(current_user), current=Depends(current_session), db=Depends(db_session)):
    rows = db.scalars(
        select(LoginSession)
        .where(LoginSession.user_id == user.id, LoginSession.expires_at > now())
        .order_by(LoginSession.created_at.desc())
    ).all()
    return [
        {"id": s.id, "agent": s.agent, "current": s.id == current.id, "created_at": s.created_at.isoformat() + "Z"}
        for s in rows
    ]


@router.delete("/sessions/{session_id}", status_code=204)
def revoke(session_id: str, user=Depends(current_user), db=Depends(db_session)):
    db.execute(delete(LoginSession).where(LoginSession.id == session_id, LoginSession.user_id == user.id))
    record(db, user, "session.revoked")
    db.commit()


@router.post("/2fa/setup")
def setup_factor(data: PasswordInput, request: Request, user=Depends(current_user), db=Depends(db_session)):
    rate_limit(request, "sensitive", user.email, limit=10)
    user = locked_user(db, user.id)
    require_password(db, request, user, data)
    if user.totp_secret:
        raise HTTPException(409, "Two-factor authentication is already enabled")
    secret = pyotp.random_base32()
    user.pending_totp = request.app.state.crypto.wrap(secret.encode())
    user.pending_totp_at = now()
    db.commit()
    return {"secret": secret, "uri": pyotp.TOTP(secret).provisioning_uri(user.email, issuer_name="Secure Vault")}


@router.post("/2fa/enable")
def enable_factor(
    data: CodeInput,
    request: Request,
    user=Depends(current_user),
    current=Depends(current_session),
    db=Depends(db_session),
):
    rate_limit(request, "2fa", user.email, limit=10)
    user = locked_user(db, user.id)
    if not user.pending_totp or not user.pending_totp_at or user.pending_totp_at < now() - timedelta(minutes=10):
        raise HTTPException(400, "Start two-factor setup again")
    secret = request.app.state.crypto.unwrap(user.pending_totp).decode()
    if not pyotp.TOTP(secret).verify(data.code, valid_window=1):
        raise HTTPException(400, "Incorrect authentication code")
    user.totp_secret = user.pending_totp
    user.pending_totp = None
    user.pending_totp_at = None
    codes = [secrets.token_hex(8) for _ in range(8)]
    user.recovery_codes = [digest(code) for code in codes]
    user.last_totp_step = -1
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id, LoginSession.id != current.id))
    record(db, user, "two_factor.enabled")
    db.commit()
    return {"recovery_codes": codes}


@router.post("/2fa/disable")
def disable_factor(data: PasswordInput, request: Request, user=Depends(current_user), db=Depends(db_session)):
    rate_limit(request, "sensitive", user.email, limit=10)
    user = locked_user(db, user.id)
    require_password(db, request, user, data)
    user.totp_secret = None
    user.pending_totp = None
    user.recovery_codes = []
    db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
    record(db, user, "two_factor.disabled")
    db.commit()
    return {"message": "Two-factor authentication disabled. Sign in again."}


@router.post("/avatar")
def avatar(request: Request, file: UploadFile = File(...), user=Depends(current_user), db=Depends(db_session)):
    raw = file.file.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(413, "Avatar must be smaller than 2 MiB")
    try:
        with Image.open(io.BytesIO(raw)) as img:
            if img.width * img.height > 16_000_000:
                raise ValueError("Too many pixels")
            img = ImageOps.fit(ImageOps.exif_transpose(img).convert("RGB"), (512, 512))
            buf = io.BytesIO()
            img.save(buf, "JPEG", quality=85)
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        raise HTTPException(400, "Choose a valid image smaller than 16 megapixels") from None
    key = f"avatars/{user.id}/{secrets.token_hex(16)}.jpg"
    with request.app.state.sessions.begin() as journal:
        journal.add(StorageGarbage(key=key))
    try:
        user = locked_user(db, user.id)
        request.app.state.storage.put(key, buf.getvalue())
        old = user.avatar_key
        user.avatar_key = key
        if old:
            db.merge(StorageGarbage(key=old))
        db.execute(delete(StorageGarbage).where(StorageGarbage.key == key))
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(503, "Avatar upload failed. Please retry.") from None
    return {"message": "Avatar updated"}


@router.get("/avatar")
def get_avatar(request: Request, user=Depends(current_user)):
    if not user.avatar_key:
        raise HTTPException(404, "No avatar")
    return Response(request.app.state.storage.get(user.avatar_key), media_type="image/jpeg")


def delete_account_records(db, user, actor):
    versions = db.scalars(select(FileVersion).join(VaultFile).where(VaultFile.owner_id == user.id)).all()
    for version in versions:
        db.merge(StorageGarbage(key=version.storage_key))
    if user.avatar_key:
        db.merge(StorageGarbage(key=user.avatar_key))
    record(db, actor, "account.deleted", detail=f"Account ID {user.id}", owner_id=user.id)
    db.flush()
    db.delete(user)


@router.delete("/account", status_code=204)
def delete_account(
    data: PasswordInput, request: Request, response: Response, user=Depends(current_user), db=Depends(db_session)
):
    rate_limit(request, "sensitive", user.email, limit=10)
    user = locked_user(db, user.id)
    require_password(db, request, user, data)
    if user.role == "admin":
        raise HTTPException(400, "Transfer administration and demote this account before deletion")
    delete_account_records(db, user, user)
    db.commit()
    response.delete_cookie("vault_session", path="/api")
