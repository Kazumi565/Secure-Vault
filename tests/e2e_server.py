"""Disposable browser-test server. Never connects to the normal database."""

import tempfile
from pathlib import Path

from cryptography.fernet import Fernet

from app.config import Settings
from app.main import create_app
from app.manage import upgrade
from app.models import Account, FileVersion, Folder, VaultFile
from app.security import hash_password

directory = Path(tempfile.mkdtemp(prefix="secure-vault-browser-"))
settings = Settings(
    _env_file=None,
    environment="test",
    testing=True,
    storage_backend="local",
    email_provider="console",
    cookie_secure=False,
    master_key=Fernet.generate_key().decode(),
    database_url=f"sqlite:///{directory}/test.db",
    storage_path=directory / "objects",
    login_limit=100,
    frontend_url="http://localhost:3001",
)
upgrade(settings)
app = create_app(settings=settings)
with app.state.sessions.begin() as db:
    db.add(
        Account(
            email="browser@example.com",
            hashed_password=hash_password("BrowserTestPassword123!"),
            verified=True,
            full_name="Mihai Bargan",
            role="admin",
        )
    )

# Fictional sample files used only by the disposable browser-test server.

with app.state.sessions.begin() as db:
    user = db.get(Account, 1)
    folder = Folder(owner_id=user.id, name="Projects")
    db.add(folder)
    db.flush()
    samples = [
        (
            "Getting started.md",
            "text/markdown",
            b"# Welcome to your vault\nThese are demonstration files.\n",
            ["guide"],
        ),
        ("Project budget.csv", "text/csv", b"Item,Amount\nHosting,12\nDomain,10\n", ["work"]),
        ("Release checklist.txt", "text/plain", b"Review changes\nRun tests\nBack up data\n", ["work"]),
    ]
    for number, (filename, mime, data, tags) in enumerate(samples):
        key = f"{user.id}/sample-{number}.bin"
        blob, wrapped = app.state.crypto.encrypt(data, key)
        app.state.storage.put(key, blob)
        item = VaultFile(
            owner_id=user.id, folder_id=folder.id, filename=filename, mime_type=mime, size_bytes=len(data), tags=tags
        )
        db.add(item)
        db.flush()
        db.add(FileVersion(file_id=item.id, number=1, storage_key=key, wrapped_key=wrapped, size_bytes=len(data)))
        user.used_bytes += len(data)
