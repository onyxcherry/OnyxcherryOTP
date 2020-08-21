def test_cookie_security_flags(test_client, init_database):
    response = test_client.post(
        "/auth/login",
        data=dict(
            username="josh_9", password="m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
        ),
        follow_redirects=False,
    )
    cookie_header = response.headers.get("Set-Cookie")
    assert "Path=/" in cookie_header
    assert "SameSite=Strict" in cookie_header
    assert "HttpOnly" in cookie_header
    # Https required
    # assert 'Secure' in cookie_header
