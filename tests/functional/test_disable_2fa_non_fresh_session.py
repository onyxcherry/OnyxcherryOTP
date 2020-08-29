import pyotp
from helping import (
    deactivate_2fa,
    delete_session_cookie,
    enable_user_2fa,
    refresh_session,
    send_otp_code,
    sign_in,
    sign_in_remember,
)


def test_disable_2fa_non_fresh_session(test_client, init_database):
    sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_token = enable_user_2fa(test_client)
    delete_session_cookie(test_client)
    sign_in_remember(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_code = pyotp.TOTP(otp_token).now()
    send_otp_code(test_client, otp_code)
    delete_session_cookie(test_client)
    index_response = test_client.get("/")
    assert b"Hello, dave" in index_response.data
    deactivate_2fa_first_response = deactivate_2fa(test_client)
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in deactivate_2fa_first_response.data
    )
    refresh_session(test_client, "wselfknskjdksdaiujlj")
    deactivate_2fa_second_response = deactivate_2fa(test_client)
    assert b"Deactivated 2FA" in deactivate_2fa_second_response.data
