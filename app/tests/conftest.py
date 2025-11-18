# app/tests/conftest.py
import importlib
import os
import secrets
import uuid

import boto3
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from moto import mock_aws

os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(32))
os.environ.setdefault("MASTER_KEY", Fernet.generate_key().decode())
os.environ.setdefault("EMAIL_FROM", "noreply@example.com")
os.environ.setdefault("EMAIL_PROVIDER", "console")
os.environ.setdefault("AWS_REGION", "eu-north-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("S3_BUCKET_NAME", "securevault-tests")

from app.main import app
from app import models
from app.database import engine
from app.auth import get_admin_user   # we’ll override this

# ───────────────────────────────  constants  ──────────────────────────────
AWS_REGION        = "eu-north-1"
BUCKET_NAME       = os.getenv("S3_BUCKET_NAME", "securevault-tests")

# ───────────────────────── create fresh DB once ───────────────────────────
@pytest.fixture(scope="session", autouse=True)
def _create_schema():
    models.Base.metadata.drop_all(bind=engine)
    models.Base.metadata.create_all(bind=engine)

# ─────────────────────────── fake S3 for every test ───────────────────────
@pytest.fixture(autouse=True)
def _mock_s3(monkeypatch):
    """
    * starts moto
    * creates the bucket with correct LocationConstraint
    * reloads & patches app.utils.s3_utils so it uses the mocked client/bucket
    * overrides the admin-check so all tests can hit /admin/audit
    """
    # Make env-vars point to fake AWS **before** the app code (re)reads them
    monkeypatch.setenv("AWS_ACCESS_KEY_ID",     "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_REGION",            AWS_REGION)
    monkeypatch.setenv("S3_BUCKET_NAME",        BUCKET_NAME)

    with mock_aws():                # moto intercepts all AWS calls
        # create bucket with proper region
        s3 = boto3.client(
            "s3",
            region_name=AWS_REGION,
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
        )
        s3.create_bucket(
            Bucket=BUCKET_NAME,
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION},
        )

        # reload utils so it picks up env vars, replace its client & bucket name
        from app.utils import s3_utils
        importlib.reload(s3_utils)
        s3_utils.s3             = s3
        s3_utils.S3_BUCKET_NAME = BUCKET_NAME

        # allow anyone to hit the admin endpoints in tests
        app.dependency_overrides[get_admin_user] = lambda: object()

        yield            # run the actual test

        # cleanup
        app.dependency_overrides.clear()

# ───────────────────────────── test client  ───────────────────────────────
@pytest.fixture
def client():
    return TestClient(app)

# ───── helper: register user and return auth header (Bearer …) ────────────
@pytest.fixture
def auth_header(client):
    email = f"u{uuid.uuid4().hex[:6]}@mail.com"
    pwd   = "P@ssw0rd!"
    client.post("/register", json={"email": email, "password": pwd, "full_name": ""})
    res = client.post(
        "/login",
        data={"username": email, "password": pwd},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
