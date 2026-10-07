import os
import re
import uuid

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from app.config import Settings
from app.main import create_app
from app.manage import upgrade

PASSWORD = "CorrectHorseBattery123!"


@pytest.fixture
def test_database(tmp_path):
    target = os.environ.get("VAULT_TEST_POSTGRES_URL")
    if not target:
        yield f"sqlite:///{tmp_path}/test.db"
        return
    url = make_url(target)
    if (
        url.get_backend_name() != "postgresql"
        or url.database != "secure_vault_test"
        or url.host not in {"localhost", "127.0.0.1"}
    ):
        raise ValueError("PostgreSQL tests require a local, dedicated secure_vault_test database")
    schema = "vault_test_" + uuid.uuid4().hex
    admin = create_engine(url)
    with admin.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))
    try:
        yield url.update_query_dict({"options": f"-csearch_path={schema}"}).render_as_string(hide_password=False)
    finally:
        with admin.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture
def app(tmp_path, test_database):
    settings = Settings(
        _env_file=None,
        master_key=Fernet.generate_key().decode(),
        testing=True,
        environment="test",
        storage_backend="local",
        email_provider="console",
        cookie_secure=False,
        database_url=test_database,
        storage_path=tmp_path / "objects",
        max_upload_bytes=1024 * 1024,
        max_storage_bytes=2 * 1024 * 1024,
    )
    upgrade(settings)
    application = create_app(settings=settings)
    yield application
    application.state.engine.dispose()


@pytest.fixture
def client(app):
    with TestClient(app) as client:
        yield client


def create_user(app, email="person@example.com", verified=True):
    client = TestClient(app)
    assert (
        client.post(
            "/api/auth/register", json={"email": email, "password": PASSWORD, "full_name": "Test Person"}
        ).status_code
        == 201
    )
    if verified:
        message = next(
            m for m in reversed(app.state.sent_mail) if m["to"] == email and m["subject"] == "Verify your email"
        )
        token = re.search(r"token=([\w-]+)", message["body"]).group(1)
        assert client.post("/api/auth/verify", json={"token": token}).status_code == 200
    result = client.post("/api/auth/login", json={"email": email, "password": PASSWORD})
    assert result.status_code == 200
    client.headers["X-CSRF-Token"] = result.json()["csrf_token"]
    return client


@pytest.fixture
def user(app):
    return create_user(app)


def upload(client, name="notes.txt", data=b"private content"):
    return client.post("/api/files", files={"file": (name, data, "application/octet-stream")})
