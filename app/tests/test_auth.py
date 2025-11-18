def test_register_and_login(client):
    email = "joe@example.com"
    pwd = "Secret123!"

    # register
    res = client.post(
        "/register",
        json={
            "email": email,
            "password": pwd,
            "full_name": ""})
    assert res.status_code == 200

    # bad login
    bad = client.post(
        "/login",
        data={
            "username": email,
            "password": "wrong"},
        headers={
            "Content-Type": "application/x-www-form-urlencoded"})
    assert bad.status_code == 401

    # good login
    ok = client.post(
        "/login",
        data={
            "username": email,
            "password": pwd},
        headers={
            "Content-Type": "application/x-www-form-urlencoded"})
    assert ok.status_code == 200
    assert "access_token" in ok.json()
