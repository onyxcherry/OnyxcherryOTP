import pyotp
from helping import (
    delete_session_cookie,
    enable_user_2fa,
    send_otp_code,
    sign_in,
    sign_in_remember,
)


def test_remember_me_with_2fa_enabled(test_client, init_database):
    sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_token = enable_user_2fa(test_client)
    delete_session_cookie(test_client)
    sign_in_remember(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_code = pyotp.TOTP(otp_token).now()
    send_otp_code(test_client, otp_code)
    delete_session_cookie(test_client)
    index_response = test_client.get("/")
    assert b"Hello, dave" in index_response.data
