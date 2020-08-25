def test_logout(test_client, init_database):
    test_client.post(
        "/auth/login",
        data=dict(username="straw_berry", password="EJew@MHHQ7x-g.4<"),
        follow_redirects=False,
    )
    logout_response = test_client.get("/auth/logout", follow_redirects=False)
    cookie_header = logout_response.headers.get("Set-Cookie")
    assert "session=;" in cookie_header
