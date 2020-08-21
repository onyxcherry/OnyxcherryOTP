def test_login_without_2fa(test_client, init_database):
    login_response = test_client.post(
        "/auth/login",
        data=dict(username="straw_berry", password="EJew@MHHQ7x-g.4<"),
        follow_redirects=True,
    )

    assert b'Hello, straw_berry' in login_response.data