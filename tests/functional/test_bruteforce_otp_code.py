import pyotp
from helping import (
    delete_session_cookie,
    enable_user_2fa,
    send_otp_code,
    sign_in,
)


def test_bruteforce_otp_code(test_client, init_database):
    sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_token = enable_user_2fa(test_client)
    delete_session_cookie(test_client)
    sign_in(test_client, "dave", "wselfknskjdksdaiujlj")

    for _ in range(3):
        response = send_otp_code(test_client, "invalid")
        assert response.status_code == 200
    for _ in range(5):
        response = send_otp_code(test_client, "invalid")
        assert response.status_code == 401

    otp_code = pyotp.TOTP(otp_token).now()
    valid_otp_code_response = send_otp_code(test_client, otp_code)
    assert valid_otp_code_response.status_code == 401
    index_response = test_client.get("/", follow_redirects=True)
    assert b"Hello, dave" not in index_response.data
