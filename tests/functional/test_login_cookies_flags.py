from helping import sign_in_no_fr


def test_cookie_security_flags(test_client, init_database):
    response = sign_in_no_fr(
        test_client, "josh_9", "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    cookie_header = response.headers.get("Set-Cookie")
    assert "Path=/" in cookie_header
    assert "SameSite=Strict" in cookie_header
    assert "HttpOnly" in cookie_header
    # Https required
    # assert 'Secure' in cookie_header
