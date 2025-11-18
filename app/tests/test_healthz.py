"""Test health check endpoint."""


def test_healthz_endpoint(client):
    """Health check should return 200 with status info."""
    res = client.get("/healthz")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "checks" in data
    assert data["checks"]["database"] == "ok"
    assert data["checks"]["s3"] == "ok"
