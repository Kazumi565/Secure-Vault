from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import event, func, select

from app.maintenance import run_maintenance
from app.models import Account, FileVersion, StorageGarbage, VaultFile, now
from tests.conftest import PASSWORD, upload


def test_encryption_roundtrip_tamper_and_key_wrapping(app, user):
    content = b"sensitive bytes" * 10
    response = upload(user, data=content)
    assert response.status_code == 201, response.text
    fid = response.json()["id"]
    assert user.get(f"/api/files/{fid}/download").content == content
    with app.state.sessions() as db:
        version = db.scalar(select(FileVersion))
        raw_key = app.state.crypto.unwrap(version.wrapped_key)
        blob = app.state.storage.get(version.storage_key)
        assert content not in blob
        assert raw_key.hex() not in version.wrapped_key
        app.state.storage.put(version.storage_key, blob[:-1] + bytes([blob[-1] ^ 1]))
    assert user.get(f"/api/files/{fid}/download").status_code == 503


def test_numeric_size_sort_search_and_tags(user):
    for name, size in [("medium.txt", 1024), ("small.txt", 900), ("large.txt", 20000)]:
        assert upload(user, name, b"x" * size).status_code == 201
    data = user.get("/api/files?sort=size&order=asc").json()["items"]
    assert [x["size_bytes"] for x in data] == [900, 1024, 20000]
    assert user.get("/api/files?search=medium").json()["total"] == 1
    fid = data[0]["id"]
    assert (
        user.patch(f"/api/files/{fid}", json={"filename": "small.txt", "tags": ["Work", "work", "private"]}).status_code
        == 200
    )
    assert user.get("/api/files?tag=work").json()["total"] == 1
    assert user.get("/api/files?tag=absent").json()["total"] == 0


def test_versions_trash_restore_and_quota(user):
    fid = upload(user, data=b"first").json()["id"]
    assert user.post(f"/api/files/{fid}/versions", files={"file": ("notes.txt", b"second")}).status_code == 201
    assert user.get("/api/storage").json()["used_bytes"] == 11
    assert user.get(f"/api/files/{fid}/download").content == b"second"
    assert user.post(f"/api/files/{fid}/versions/1/restore").status_code == 200
    assert user.get(f"/api/files/{fid}/download").content == b"first"
    assert user.delete(f"/api/files/{fid}/versions/1").status_code == 409
    assert user.delete(f"/api/files/{fid}/versions/2").status_code == 204
    assert user.get("/api/storage").json()["used_bytes"] == 5
    assert user.delete(f"/api/files/{fid}").status_code == 204
    assert user.get("/api/files").json()["total"] == 0
    assert user.get("/api/files?trash=true").json()["total"] == 1
    assert user.get(f"/api/files/{fid}/download").status_code == 404
    assert user.get("/api/storage").json()["trash_bytes"] == 5
    assert user.post(f"/api/files/{fid}/restore").status_code == 200
    assert user.delete(f"/api/files/{fid}/permanent").status_code == 409
    user.delete(f"/api/files/{fid}")
    assert user.delete(f"/api/files/{fid}/permanent").status_code == 204
    assert user.get("/api/storage").json()["used_bytes"] == 0


def test_concurrent_quota_reservation(app, user):
    app.state.settings.max_storage_bytes = 1024
    cookie = dict(user.cookies)
    csrf = user.headers["X-CSRF-Token"]

    def send(number):
        client = TestClient(app)
        client.cookies.update(cookie)
        client.headers["X-CSRF-Token"] = csrf
        return upload(client, f"{number}.txt", b"x" * 700).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(send, [1, 2]))
    assert statuses == [201, 413]
    assert user.get("/api/storage").json()["used_bytes"] == 700


def test_storage_failure_does_not_charge_quota(app, user, monkeypatch):
    def fail(*args):
        raise OSError("synthetic storage failure")

    monkeypatch.setattr(app.state.storage, "put", fail)
    assert upload(user).status_code == 503
    assert user.get("/api/storage").json()["used_bytes"] == 0
    assert user.get("/api/files").json()["total"] == 0


def test_database_failure_leaves_durable_cleanup(app, user):
    def fail(*args):
        raise RuntimeError("synthetic database write failure")

    event.listen(FileVersion, "before_insert", fail)
    try:
        assert upload(user).status_code == 503
    finally:
        event.remove(FileVersion, "before_insert", fail)
    with app.state.sessions.begin() as db:
        marker = db.scalar(select(StorageGarbage))
        assert marker
        key = marker.key
        assert app.state.storage.get(key)
        marker.created_at = now() - timedelta(hours=2)
    stats = run_maintenance(app)
    assert stats["objects_removed"] == 1
    assert not app.state.storage.path(key).exists()
    assert user.get("/api/storage").json()["used_bytes"] == 0


def test_share_password_limit_and_revocation(app, user):
    fid = upload(user).json()["id"]
    created = user.post(f"/api/files/{fid}/shares", json={"password": "shared-secret", "max_downloads": 1})
    token = created.json()["url"].rsplit("/", 1)[1]
    visitor = TestClient(app)
    assert visitor.post(f"/api/shared/{token}/download", json={"password": "wrong"}).status_code == 403
    assert visitor.post(f"/api/shared/{token}/download", json={"password": "shared-secret"}).status_code == 200
    assert visitor.post(f"/api/shared/{token}/download", json={"password": "shared-secret"}).status_code == 404
    other = user.post(f"/api/files/{fid}/shares", json={}).json()
    assert user.delete(f"/api/files/{fid}/shares/{other['id']}").status_code == 204
    assert visitor.post("/api/shared/" + other["url"].rsplit("/", 1)[1] + "/download", json={}).status_code == 404


def test_folder_ownership_and_deletion(app, user):
    from tests.conftest import create_user

    other = create_user(app, "other@example.com")
    folder = user.post("/api/folders", json={"name": "Work"}).json()["id"]
    assert other.post("/api/files", files={"file": ("a.txt", b"test")}, data={"folder_id": folder}).status_code == 404
    result = user.post("/api/files", files={"file": ("a.txt", b"test")}, data={"folder_id": folder})
    assert result.status_code == 201
    assert user.get(f"/api/files?folder_id={folder}").json()["total"] == 1
    assert user.delete(f"/api/folders/{folder}").status_code == 204
    assert user.get("/api/files").json()["items"][0]["folder_id"] is None


def test_account_deletion_schedules_every_object(app, user):
    fid = upload(user).json()["id"]
    user.post("/api/auth/forgot-password", json={"email": "person@example.com"})
    assert user.request("DELETE", "/api/auth/account", json={"password": PASSWORD}).status_code == 204
    with app.state.sessions() as db:
        assert db.scalar(select(func.count()).select_from(Account)) == 0
        assert db.get(VaultFile, fid) is None
        assert db.scalar(select(func.count()).select_from(StorageGarbage)) == 1


def test_safe_download_filename_and_no_html_preview(user):
    assert upload(user, "../bad.txt").status_code == 400
    fid = upload(user, "pagină.html", b"<script>alert(1)</script>").json()["id"]
    response = user.get(f"/api/files/{fid}/download?inline=true")
    assert response.headers["content-disposition"].startswith("attachment")
    assert response.headers["content-type"] == "application/octet-stream"


def test_expired_trash_cleanup(app, user):
    fid = upload(user).json()["id"]
    user.delete(f"/api/files/{fid}")
    with app.state.sessions.begin() as db:
        db.get(VaultFile, fid).deleted_at = now() - timedelta(days=31)
    assert run_maintenance(app)["expired_files"] == 1
    assert user.get("/api/storage").json()["used_bytes"] == 0
