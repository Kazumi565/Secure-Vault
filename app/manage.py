import argparse
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.engine import make_url

from app.config import Settings
from app.database import make_engine, session_factory
from app.models import Account, FileVersion, MailMessage
from app.security import Crypto


def upgrade(settings, engine=None):
    url = make_url(settings.database_url)
    if url.drivername.startswith("sqlite") and url.database not in (None, "", ":memory:"):
        Path(url.database).parent.mkdir(parents=True, exist_ok=True)
    cfg = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    cfg.attributes["settings"] = settings
    if engine is not None:
        cfg.attributes["engine"] = engine
    command.upgrade(cfg, "head")


def main():
    parser = argparse.ArgumentParser(description="Secure Vault maintenance")
    parser.add_argument("command", choices=["upgrade", "admin", "maintenance", "import-legacy", "rewrap-keys"])
    parser.add_argument("--email")
    parser.add_argument("--confirm-backup", action="store_true")
    args = parser.parse_args()
    settings = Settings()
    if args.command == "upgrade":
        upgrade(settings)
        print("Database schema is current.")
        return
    engine = make_engine(settings.database_url)
    if args.command == "admin":
        if not args.email:
            parser.error("--email is required")
        with session_factory(engine).begin() as db:
            user = db.scalar(select(Account).where(Account.email == args.email.casefold()))
            if not user or not user.verified:
                parser.error("Register and verify the account first")
            user.role = "admin"
        print("Administrator role assigned.")
    elif args.command == "import-legacy":
        if not args.confirm_backup:
            parser.error("Back up the database, objects, and keys, then pass --confirm-backup")
        from app.legacy import import_legacy
        from app.storage import make_storage

        print(json.dumps(import_legacy(engine, Crypto(settings), make_storage(settings))))
    elif args.command == "rewrap-keys":
        if not args.confirm_backup:
            parser.error("Back up the database and keys, then pass --confirm-backup")
        crypto = Crypto(settings)
        with session_factory(engine).begin() as db:
            count = 0
            for version in db.scalars(select(FileVersion)):
                version.wrapped_key = crypto.wrap(crypto.unwrap(version.wrapped_key))
                count += 1
            for user in db.scalars(select(Account)):
                for attr in ["totp_secret", "pending_totp"]:
                    value = getattr(user, attr)
                    if value:
                        setattr(user, attr, crypto.wrap(crypto.unwrap(value)))
            for mail in db.scalars(select(MailMessage)):
                mail.encrypted_payload = crypto.wrap(crypto.unwrap(mail.encrypted_payload))
        print(f"Rewrapped {count} file keys and protected account/email data.")
    else:
        from app.main import create_app
        from app.maintenance import run_maintenance

        print(json.dumps(run_maintenance(create_app(settings=settings, engine=engine))))


if __name__ == "__main__":
    main()
