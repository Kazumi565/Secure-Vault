import io
from datetime import timedelta

import boto3
import pytest
from botocore.exceptions import ClientError
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from moto import mock_aws
from PIL import Image
from sqlalchemy import select, text

from app.config import Settings
from app.legacy import import_legacy
from app.mail import flush_mail
from app.manage import upgrade
from app.models import Account, FileVersion, MailMessage, now
from app.security import Crypto, hash_password
from app.storage import S3Storage
from tests.conftest import create_user, upload


def test_migrations_idempotent_and_readiness(app, client):
    upgrade(app.state.settings, app.state.engine)
    assert client.get("/readyz").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok"}


def test_s3_roundtrip_missing_and_error_distinction(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="vault-test-bucket")
        settings = Settings(
            _env_file=None,
            master_key=Fernet.generate_key().decode(),
            storage_backend="s3",
            s3_bucket_name="vault-test-bucket",
            aws_region="us-east-1",
        )
        storage = S3Storage(settings)
        storage.put("1/file.bin", b"ciphertext")
        assert storage.get("1/file.bin") == b"ciphertext"
        assert storage.size("1/file.bin") == 10
        storage.delete("1/file.bin")
        with pytest.raises(FileNotFoundError):
            storage.size("1/file.bin")

        def denied(**kwargs):
            raise ClientError({"Error": {"Code": "AccessDenied"}}, "HeadObject")

        monkeypatch.setattr(storage.client, "head_object", denied)
        with pytest.raises(ClientError):
            storage.size("1/file.bin")


def test_master_key_rotation_preserves_decryption(app, user):
    fid = upload(user).json()["id"]
    old = app.state.settings.master_key
    updated = app.state.settings.model_copy(
        update={"master_key": Fernet.generate_key().decode(), "previous_master_keys": old}
    )
    crypto = Crypto(updated)
    with app.state.sessions.begin() as db:
        version = db.scalar(select(FileVersion))
        version.wrapped_key = crypto.wrap(crypto.unwrap(version.wrapped_key))
    app.state.crypto = Crypto(updated.model_copy(update={"previous_master_keys": ""}))
    assert user.get(f"/api/files/{fid}/download").content == b"private content"


def test_legacy_import_authenticates_data_and_wraps_keys(app):
    key = b"k" * 32
    cipher = AES.new(key, AES.MODE_EAX)
    encrypted, tag = cipher.encrypt_and_digest(b"legacy data")
    app.state.storage.put("7/original.bin", cipher.nonce + tag + encrypted)
    with app.state.engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, hashed_password TEXT, is_verified BOOLEAN, role TEXT)"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE files (id INTEGER PRIMARY KEY, owner_id INTEGER, filename TEXT, stored_filename TEXT, encryption_key TEXT)"
            )
        )
        conn.execute(
            text("INSERT INTO users VALUES (7,:email,:hash,true,'user')"),
            {"email": "legacy@example.com", "hash": hash_password("LongLegacyPassword123")},
        )
        conn.execute(text("INSERT INTO files VALUES (9,7,'legacy.txt','original.bin',:key)"), {"key": key.hex()})
    result = import_legacy(app.state.engine, app.state.crypto, app.state.storage)
    assert result == {"accounts": 1, "files": 1}
    with app.state.sessions() as db:
        assert db.get(Account, 7).used_bytes == 11
        version = db.scalar(select(FileVersion))
        assert (
            app.state.crypto.decrypt(
                app.state.storage.get(version.storage_key), version.wrapped_key, version.storage_key, version.format
            )
            == b"legacy data"
        )
        assert db.execute(text("SELECT encryption_key FROM files")).scalar() == "[migrated]"
    with pytest.raises(ValueError):
        import_legacy(app.state.engine, app.state.crypto, app.state.storage)


def test_failed_legacy_import_does_not_scrub_original_keys(app):
    with app.state.engine.begin() as conn:
        conn.execute(text("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, hashed_password TEXT)"))
        conn.execute(
            text(
                "CREATE TABLE files (id INTEGER PRIMARY KEY, owner_id INTEGER, filename TEXT, stored_filename TEXT, encryption_key TEXT)"
            )
        )
        conn.execute(text("INSERT INTO users VALUES (1,'legacy@example.com','unused hash')"))
        conn.execute(text("INSERT INTO files VALUES (1,1,'missing.txt','missing.bin','original-key')"))
    with pytest.raises(FileNotFoundError):
        import_legacy(app.state.engine, app.state.crypto, app.state.storage)
    with app.state.sessions() as db:
        assert db.get(Account, 1) is None
        assert db.execute(text("SELECT encryption_key FROM files")).scalar() == "original-key"


def test_mail_retry_does_not_rollback_registration(app, monkeypatch):
    app.state.settings.testing = False
    app.state.settings.email_provider = "smtp"
    app.state.settings.smtp_host = "example.invalid"

    def fail(*args, **kwargs):
        raise OSError("simulated provider failure")

    monkeypatch.setattr("smtplib.SMTP", fail)
    client = TestClient(app)
    r = client.post("/api/auth/register", json={"email": "retry@example.com", "password": "LongPasswordWith123"})
    assert r.status_code == 201
    with app.state.sessions.begin() as db:
        message = db.scalar(select(MailMessage))
        assert message.attempts == 1 and "token=" not in message.encrypted_payload
        message.available_at = now() - timedelta(minutes=1)
    app.state.settings.testing = True
    flush_mail(app)
    assert len(app.state.sent_mail) == 1
    with app.state.sessions() as db:
        assert db.scalar(select(MailMessage)) is None


def test_admin_deletes_exact_duplicate_filename(app, user):
    other = create_user(app, "other@example.com")
    target = upload(user, "same.txt", b"first").json()["id"]
    survivor = upload(other, "same.txt", b"second").json()["id"]
    with app.state.sessions.begin() as db:
        db.scalar(select(Account).where(Account.email == "person@example.com")).role = "admin"
    assert user.delete(f"/api/admin/files/{target}").status_code == 204
    assert other.get(f"/api/files/{survivor}/download").content == b"second"
    assert user.get(f"/api/files/{target}/download").status_code == 404


def test_image_is_reencoded_and_owned(app, user):
    image = io.BytesIO()
    Image.new("RGB", (800, 600), "blue").save(image, "PNG")
    assert user.post("/api/auth/avatar", files={"file": ("image.png", image.getvalue())}).status_code == 200
    result = user.get("/api/auth/avatar")
    assert result.headers["content-type"] == "image/jpeg"
    with Image.open(io.BytesIO(result.content)) as image:
        assert image.size == (512, 512)
    other = create_user(app, "other@example.com")
    assert other.get("/api/auth/avatar").status_code == 404


def test_body_limits_with_and_without_content_length(app, user):
    size = app.state.settings.max_upload_bytes + 1024 * 1024 + 10
    assert user.post("/api/files", content=b"x" * size).status_code == 413
    boundary = "vaultboundary"
    start = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()

    def chunks():
        yield start
        for _ in range(35):
            yield b"x" * 65536
        yield f"\r\n--{boundary}--\r\n".encode()

    assert (
        user.post(
            "/api/files", content=chunks(), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
        ).status_code
        == 413
    )


def test_production_config_rejects_insecure_settings():
    with pytest.raises(ValueError):
        Settings(_env_file=None, master_key=Fernet.generate_key().decode(), environment="production")


def test_backup_restore_preserves_download_and_never_overwrites(app, user, tmp_path):
    from app.backup import backup, restore
    from app.main import create_app

    if app.state.engine.dialect.name != "sqlite":
        pytest.skip("Snapshot helper is specific to SQLite/local storage")
    fid = upload(user).json()["id"]
    archive = tmp_path / "snapshot.zip"
    with pytest.raises(ValueError):
        backup(app.state.settings, archive)
    backup(app.state.settings, archive, stopped=True)
    with pytest.raises(FileExistsError):
        backup(app.state.settings, archive, stopped=True)
    destination = tmp_path / "restored"
    restore(archive, destination)
    with pytest.raises(FileExistsError):
        restore(archive, destination)
    restored_app = create_app(
        settings=app.state.settings.model_copy(
            update={"database_url": f"sqlite:///{destination}/vault.db", "storage_path": destination / "objects"}
        )
    )
    restored = TestClient(restored_app)
    restored.cookies.update(user.cookies)
    assert restored.get(f"/api/files/{fid}/download").content == b"private content"
    assert not (destination / ".env").exists()


def test_restore_rejects_corruption_and_path_traversal(tmp_path):
    import json
    import zipfile

    from app.backup import restore

    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(
            "manifest.json",
            json.dumps(
                {
                    "format": 1,
                    "files": {
                        "vault.db": {"bytes": 3, "sha256": "incorrect"},
                        "objects/../../escape": {"bytes": 3, "sha256": "incorrect"},
                    },
                }
            ),
        )
        z.writestr("vault.db", b"bad")
        z.writestr("objects/../../escape", b"bad")
    with pytest.raises(ValueError):
        restore(archive, tmp_path / "restore")
    assert not (tmp_path / "escape").exists()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(
            "manifest.json", json.dumps({"format": 1, "files": {"vault.db": {"bytes": 3, "sha256": "incorrect"}}})
        )
        z.writestr("vault.db", b"bad")
    with pytest.raises(ValueError):
        restore(archive, tmp_path / "restore")
    assert not (tmp_path / "restore").exists()


@pytest.mark.parametrize("implicit_tls", [False, True])
def test_smtp_verifies_server_certificate(app, monkeypatch, implicit_tls):
    import ssl

    from app.mail import enqueue

    contexts, sent = [], []

    class Transport:
        def __init__(self, host, port, **options):
            if implicit_tls:
                contexts.append(options["context"])

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def starttls(self, *, context):
            contexts.append(context)

        def send_message(self, mail):
            sent.append(mail)

    monkeypatch.setattr("smtplib.SMTP_SSL" if implicit_tls else "smtplib.SMTP", Transport)
    app.state.settings.testing = False
    app.state.settings.email_provider = "smtp"
    app.state.settings.smtp_host = "mail.example.com"
    app.state.settings.smtp_ssl = implicit_tls
    with app.state.sessions.begin() as db:
        enqueue(db, app, "person@example.com", "Test delivery", "Message body")
    flush_mail(app)
    assert len(sent) == len(contexts) == 1
    assert contexts[0].verify_mode == ssl.CERT_REQUIRED
    assert contexts[0].check_hostname
