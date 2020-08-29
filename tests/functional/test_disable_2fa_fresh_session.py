import pyotp
from helping import (
    deactivate_2fa,
    delete_session_cookie,
    enable_user_2fa,
    send_otp_code,
    sign_in,
)


def test_disable_2fa_fresh_session(test_client, init_database):
    sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_token = enable_user_2fa(test_client)
    delete_session_cookie(test_client)
    sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_code = pyotp.TOTP(otp_token).now()
    send_otp_code(test_client, otp_code)

    index_response = test_client.get("/")
    assert b"Hello, dave" in index_response.data

    response = deactivate_2fa(test_client)
    assert b"Deactivated 2FA" in response.data
