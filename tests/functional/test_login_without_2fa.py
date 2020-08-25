from helping import sign_in


def test_login_without_2fa(test_client, init_database):
    sign_in_response = sign_in(test_client, "straw_berry", "EJew@MHHQ7x-g.4<")
    assert b"Hello, straw_berry" in sign_in_response.data
