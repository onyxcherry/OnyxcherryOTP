from helping import sign_in


def test_logout(test_client, init_database):
    sign_in(test_client, "straw_berry", "EJew@MHHQ7x-g.4<")
    logout_response = test_client.get("/auth/logout", follow_redirects=False)
    cookie_header = logout_response.headers.get("Set-Cookie")
    assert "session=;" in cookie_header
