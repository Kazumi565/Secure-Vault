import base64
import os

import boto3

from app.database import SessionLocal
from app.models import File as FileModel
from app.tests.conftest import AWS_REGION


def _dummy_file(sz=1024):
    return os.urandom(sz)


def test_upload_and_quota(client, auth_header):
    # 1 KB file
    res = client.post(
        "/upload",
        files={
            "upload_file": (
                "a.txt",
                _dummy_file(1024),
                "text/plain")},
        headers=auth_header)
    assert res.status_code == 200
    fid = res.json()["file_id"]

    # storage-usage endpoint shows roughly 0.00 MB (<= 0.01)
    usage = client.get("/storage-usage", headers=auth_header).json()["used_mb"]
    assert usage <= 0.01

    # uploading 101 MB should fail
    too_big = client.post(
        "/upload",
        files={
            "upload_file": (
                "big.bin",
                _dummy_file(
                    101 *
                    1024 *
                    1024),
                "application/octet-stream")},
        headers=auth_header)
    assert too_big.status_code == 400

    # download preview (inline) — should NOT create audit
    client.get(f"/download/{fid}?inline=true", headers=auth_header)
    # user isn’t admin but endpoint patched for tests
    logs = client.get("/admin/audit", headers=auth_header)
    assert not any(
        "Downloaded file" in entry["action"] for entry in logs.json())


def test_encrypted_data_key_is_base64(client, auth_header):
    payload = b"secret-bytes"
    res = client.post(
        "/upload",
        files={
            "upload_file": (
                "key.bin",
                payload,
                "application/octet-stream")},
        headers=auth_header,
    )
    assert res.status_code == 200
    fid = res.json()["file_id"]

    with SessionLocal() as db:
        record = db.query(FileModel).filter(FileModel.id == fid).first()
        assert record is not None
        assert record.encrypted_data_key
        base64.b64decode(record.encrypted_data_key)

    download = client.get(f"/download/{fid}", headers=auth_header)
    assert download.status_code == 200
    assert download.content == payload


def test_upload_works_with_kms(monkeypatch, client, auth_header):
    kms = boto3.client(
        "kms",
        region_name=AWS_REGION,
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )
    key_metadata = kms.create_key(Description="test key")
    monkeypatch.delenv("MASTER_KEY", raising=False)
    monkeypatch.setenv("KMS_KEY_ID", key_metadata["KeyMetadata"]["KeyId"])

    res = client.post(
        "/upload",
        files={
            "upload_file": (
                "kms.bin",
                b"kms-encrypted",
                "application/octet-stream")},
        headers=auth_header,
    )
    assert res.status_code == 200
    fid = res.json()["file_id"]

    download = client.get(f"/download/{fid}", headers=auth_header)
    assert download.status_code == 200
    assert download.content == b"kms-encrypted"
