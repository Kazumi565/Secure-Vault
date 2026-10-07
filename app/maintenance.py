import logging
from datetime import timedelta

from sqlalchemy import delete, select

from app.auth import locked_user
from app.files import purge_file
from app.mail import flush_mail
from app.models import (
    Account,
    ActionToken,
    FileVersion,
    LoginSession,
    RateBucket,
    ShareLink,
    StorageGarbage,
    VaultFile,
    now,
)

logger = logging.getLogger(__name__)


def run_maintenance(app):
    stats = {"expired_files": 0, "objects_removed": 0, "cleanup_failures": 0}
    with app.state.sessions() as db:
        ids = list(
            db.scalars(
                select(VaultFile.id)
                .where(VaultFile.deleted_at < now() - timedelta(days=app.state.settings.trash_days))
                .limit(1000)
            )
        )
    for ident in ids:
        with app.state.sessions() as db:
            item = db.get(VaultFile, ident)
            if item:
                locked_user(db, item.owner_id)
                db.refresh(item)
                if item.deleted_at and item.deleted_at < now() - timedelta(days=app.state.settings.trash_days):
                    purge_file(db, item, None)
                    db.commit()
                    stats["expired_files"] += 1
    with app.state.sessions.begin() as db:
        for model in [ActionToken, LoginSession, RateBucket, ShareLink]:
            db.execute(delete(model).where(model.expires_at < now()))
    with app.state.sessions() as db:
        keys = list(
            db.scalars(
                select(StorageGarbage.key).where(StorageGarbage.created_at < now() - timedelta(hours=1)).limit(1000)
            )
        )
    for key in keys:
        with app.state.sessions() as db:
            # A stale marker can never delete a referenced version.
            if db.scalar(select(FileVersion.id).where(FileVersion.storage_key == key)) or db.scalar(
                select(Account.id).where(Account.avatar_key == key)
            ):
                db.execute(delete(StorageGarbage).where(StorageGarbage.key == key))
                db.commit()
                continue
            try:
                app.state.storage.delete(key)
                db.execute(delete(StorageGarbage).where(StorageGarbage.key == key))
                db.commit()
                stats["objects_removed"] += 1
            except Exception:
                stats["cleanup_failures"] += 1
                logger.warning("Object cleanup deferred for retry")
    flush_mail(app)
    return stats
