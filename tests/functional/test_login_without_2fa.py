from helping import delete_session_cookie, sign_in


def test_login_without_2fa(test_client, init_database):
    delete_session_cookie(test_client)
    sign_in_response = sign_in(test_client, "straw_berry", "EJew@MHHQ7x-g.4<")
    assert b"Hello, straw_berry" in sign_in_response.data


def test_login_taken_username(test_client, init_database):
    delete_session_cookie(test_client)
    response = sign_in(test_client, "straw_berry", "aabbccdd")
    assert b"Invalid username or password" in response.data
