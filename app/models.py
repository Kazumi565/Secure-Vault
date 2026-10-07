import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def now():
    return datetime.now(UTC).replace(tzinfo=None)


def uid():
    return uuid.uuid4().hex


class Account(Base):
    __tablename__ = "accounts"
    __table_args__ = {"sqlite_autoincrement": True}
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(Text)
    full_name: Mapped[str] = mapped_column(String(120), default="")
    role: Mapped[str] = mapped_column(String(12), default="user")
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    used_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    avatar_key: Mapped[str | None] = mapped_column(String(200))
    totp_secret: Mapped[str | None] = mapped_column(Text)
    pending_totp: Mapped[str | None] = mapped_column(Text)
    pending_totp_at: Mapped[datetime | None] = mapped_column(DateTime)
    last_totp_step: Mapped[int] = mapped_column(Integer, default=-1)
    recovery_codes: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class LoginSession(Base):
    __tablename__ = "login_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[int] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    agent: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class ActionToken(Base):
    __tablename__ = "action_tokens"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    purpose: Mapped[str] = mapped_column(String(16))
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class Folder(Base):
    __tablename__ = "vault_folders"
    __table_args__ = (UniqueConstraint("owner_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))


class VaultFile(Base):
    __tablename__ = "vault_files"
    __table_args__ = {"sqlite_autoincrement": True}
    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("accounts.id", ondelete="CASCADE"), index=True)
    folder_id: Mapped[int | None] = mapped_column(ForeignKey("vault_folders.id", ondelete="SET NULL"))
    filename: Mapped[str] = mapped_column(String(240))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    version_counter: Mapped[int] = mapped_column(Integer, default=1)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    mime_type: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, index=True)


class FileVersion(Base):
    __tablename__ = "file_versions"
    __table_args__ = (UniqueConstraint("file_id", "number"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("vault_files.id", ondelete="CASCADE"), index=True)
    number: Mapped[int] = mapped_column(Integer)
    storage_key: Mapped[str] = mapped_column(String(200), unique=True)
    wrapped_key: Mapped[str] = mapped_column(Text)
    format: Mapped[str] = mapped_column(String(12), default="gcm-v2")
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class ShareLink(Base):
    __tablename__ = "share_links"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    file_id: Mapped[int] = mapped_column(ForeignKey("vault_files.id", ondelete="CASCADE"), index=True)
    password_hash: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    downloads: Mapped[int] = mapped_column(Integer, default=0)
    max_downloads: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("accounts.id", ondelete="SET NULL"), index=True)
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("accounts.id", ondelete="SET NULL"), index=True)
    actor_email: Mapped[str] = mapped_column(String(254))
    file_id: Mapped[int | None] = mapped_column(Integer)
    filename: Mapped[str | None] = mapped_column(String(240))
    action: Mapped[str] = mapped_column(String(60), index=True)
    detail: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)


class StorageGarbage(Base):
    __tablename__ = "storage_garbage"
    key: Mapped[str] = mapped_column(String(200), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class MailMessage(Base):
    __tablename__ = "mail_outbox"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    encrypted_payload: Mapped[str] = mapped_column(Text)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    available_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


Index("ix_vault_files_owner_deleted_updated", VaultFile.owner_id, VaultFile.deleted_at, VaultFile.updated_at)
