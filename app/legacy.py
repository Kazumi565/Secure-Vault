"""Transactional import from the original schema. Storage is authenticated first."""

import base64
import mimetypes

from sqlalchemy import MetaData, Table, func, inspect, select, text, update

from app.database import session_factory
from app.models import Account, AuditEvent, FileVersion, VaultFile, now


def import_legacy(engine, crypto, storage):
    tables = inspect(engine).get_table_names()
    if not {"users", "files"}.issubset(tables):
        raise ValueError("No legacy users/files tables found")
    metadata = MetaData()
    users = Table("users", metadata, autoload_with=engine)
    files = Table("files", metadata, autoload_with=engine)
    logs = Table("audit_logs", metadata, autoload_with=engine) if "audit_logs" in tables else None
    with session_factory(engine).begin() as db:
        if db.scalar(select(func.count()).select_from(Account)):
            raise ValueError("Import requires empty v2 tables. Do not run it twice.")
        rows = db.execute(select(users)).mappings().all()
        for row in rows:
            db.add(
                Account(
                    id=row["id"],
                    email=row["email"].casefold(),
                    hashed_password=row["hashed_password"],
                    full_name=row.get("full_name") or "",
                    role=row.get("role") or "user",
                    verified=bool(row.get("is_verified")),
                    used_bytes=0,
                    created_at=row.get("created_at") or now(),
                )
            )
        db.flush()
        count = 0
        for row in db.execute(select(files)).mappings().all():
            if row["owner_id"] is None:
                raise ValueError(f"Legacy file {row['id']} has no owner. Resolve it first.")
            key = f"{row['owner_id']}/{row['stored_filename']}"
            blob = storage.get(key)
            plain_key = row.get("encryption_key")
            if plain_key and plain_key != "[migrated]":
                wrapped = crypto.wrap(bytes.fromhex(plain_key))
            elif row.get("encrypted_data_key"):
                wrapped = base64.b64decode(row["encrypted_data_key"]).decode()
                crypto.unwrap(wrapped)
            else:
                raise ValueError(f"No usable key for legacy file {row['id']}")
            data = crypto.decrypt(blob, wrapped, key, "eax-v1")
            item = VaultFile(
                id=row["id"],
                owner_id=row["owner_id"],
                filename=row["filename"],
                size_bytes=len(data),
                mime_type=mimetypes.guess_type(row["filename"])[0] or "application/octet-stream",
                created_at=row.get("upload_time") or now(),
                updated_at=row.get("upload_time") or now(),
            )
            db.add(item)
            db.flush()
            db.add(
                FileVersion(
                    file_id=item.id,
                    number=1,
                    storage_key=key,
                    wrapped_key=wrapped,
                    size_bytes=len(data),
                    format="eax-v1",
                )
            )
            db.execute(
                update(Account).where(Account.id == item.owner_id).values(used_bytes=Account.used_bytes + len(data))
            )
            if "encryption_key" in files.c:
                db.execute(update(files).where(files.c.id == row["id"]).values(encryption_key="[migrated]"))
            count += 1
        if logs is not None:
            for row in db.execute(select(logs)).mappings():
                owner = db.get(Account, row.get("user_id")) if row.get("user_id") else None
                db.add(
                    AuditEvent(
                        actor_id=owner.id if owner else None,
                        owner_id=owner.id if owner else None,
                        actor_email=owner.email if owner else "(deleted legacy account)",
                        action="legacy.event",
                        detail=(row.get("action") or "")[:500],
                        created_at=row.get("timestamp") or now(),
                    )
                )
        db.flush()
        if engine.dialect.name == "postgresql":
            for name in ["accounts", "vault_files"]:
                db.execute(
                    text(
                        f"SELECT setval(pg_get_serial_sequence('{name}', 'id'), COALESCE((SELECT MAX(id) FROM {name}), 1), EXISTS(SELECT 1 FROM {name}))"
                    )
                )
    return {"accounts": len(rows), "files": count}
