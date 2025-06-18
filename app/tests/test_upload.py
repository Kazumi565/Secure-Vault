import os

def _dummy_file(sz=1024):
    return os.urandom(sz)

def test_upload_and_quota(client, auth_header):
    # 1 KB file
    res = client.post("/upload",
        files={"upload_file": ("a.txt", _dummy_file(1024), "text/plain")},
        headers=auth_header)
    assert res.status_code == 200
    fid = res.json()["file_id"]

    # storage-usage endpoint shows roughly 0.00 MB (<= 0.01)
    usage = client.get("/storage-usage", headers=auth_header).json()["used_mb"]
    assert usage <= 0.01

    # uploading 101 MB should fail
    too_big = client.post("/upload",
        files={"upload_file": ("big.bin", _dummy_file(101*1024*1024), "application/octet-stream")},
        headers=auth_header)
    assert too_big.status_code == 400

    # download preview (inline) — should NOT create audit
    client.get(f"/download/{fid}?inline=true", headers=auth_header)
    logs = client.get("/admin/audit", headers=auth_header)  # user isn’t admin but endpoint patched for tests
    assert not any("Downloaded file" in l["action"] for l in logs.json())
