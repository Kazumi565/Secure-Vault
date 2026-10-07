import secrets
from datetime import timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import case, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.models import Account, AuditEvent, LoginSession, RateBucket, now
from app.security import digest


def db_session(request: Request):
    with request.app.state.sessions() as db:
        yield db


def current_session(request: Request, db=Depends(db_session)):
    token = request.cookies.get("vault_session")
    session = db.scalar(
        select(LoginSession).where(LoginSession.token_hash == digest(token or ""), LoginSession.expires_at > now())
    )
    if not session:
        raise HTTPException(401, "Sign in to continue")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), session.csrf):
            raise HTTPException(403, "Invalid request token. Reload the page and try again.")
    return session


def current_user(session=Depends(current_session), db=Depends(db_session)):
    user = db.get(Account, session.user_id)
    if not user:
        raise HTTPException(401, "Sign in to continue")
    return user


def verified_user(user=Depends(current_user)):
    if not user.verified:
        raise HTTPException(403, "Verify your email before accessing files")
    return user


def admin_user(user=Depends(verified_user)):
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


def rate_limit(request, scope, identity="", limit=10, seconds=900):
    # The client address comes from the trusted server, never an arbitrary header.
    host = request.client.host if request.client else "unknown"
    identities = [host] + ([identity.casefold()] if identity else [])
    for label in identities:
        key = digest(scope + ":" + label)
        instant = now()
        with request.app.state.sessions.begin() as db:
            insert = sqlite_insert if db.bind.dialect.name == "sqlite" else pg_insert
            stmt = insert(RateBucket).values(key=key, count=1, expires_at=instant + timedelta(seconds=seconds))
            stmt = stmt.on_conflict_do_update(
                index_elements=["key"],
                set_={
                    "count": case((RateBucket.expires_at <= instant, 1), else_=RateBucket.count + 1),
                    "expires_at": case(
                        (RateBucket.expires_at <= instant, instant + timedelta(seconds=seconds)),
                        else_=RateBucket.expires_at,
                    ),
                },
            ).returning(RateBucket.count)
            count = db.scalar(stmt)
        if count > limit:
            raise HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(seconds)})


def record(db, actor, action, file=None, detail="", owner_id=None):
    db.add(
        AuditEvent(
            actor_id=actor.id if actor else None,
            actor_email=actor.email if actor else "shared-link visitor",
            owner_id=file.owner_id if file else owner_id or (actor.id if actor else None),
            action=action,
            file_id=file.id if file else None,
            filename=file.filename if file else None,
            detail=detail[:500],
        )
    )


def user_json(user):
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "verified": user.verified,
        "two_factor": bool(user.totp_secret),
        "has_avatar": bool(user.avatar_key),
        "created_at": user.created_at.isoformat() + "Z",
    }
