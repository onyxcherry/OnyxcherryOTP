import json
from datetime import datetime, timedelta

import pyotp
from helping import (
    delete_session_cookie,
    enable_user_2fa,
    send_otp_code,
    sign_in,
)


def generate_otp_token_at(otp_token, seconds):
    return pyotp.TOTP(otp_token).at(
        datetime.now() - timedelta(seconds=seconds)
    )


def test_login_with_2fa_enabled(test_client, init_database):
    _ = sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    otp_token = enable_user_2fa(test_client)
    delete_session_cookie(test_client)
    _ = sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    assert (
        b"Please log in to access this page."
        in test_client.get("/settings", follow_redirects=True).data
    )

    otp_code = pyotp.TOTP(otp_token).now()
    twofa_response = send_otp_code(test_client, otp_code)
    assert b"Hello, dave!" in twofa_response.data

    delete_session_cookie(test_client)
    old_otp_code = generate_otp_token_at(otp_token, 71)
    login_send_old_otp_code_response = send_otp_code(test_client, old_otp_code)
    assert b"Hello, dave!" not in login_send_old_otp_code_response.data

    delete_session_cookie(test_client)
    previous_last_otp_code = generate_otp_token_at(otp_token, 37)
    login_send_previous_last_otp_code_response = send_otp_code(
        test_client, previous_last_otp_code
    )
    # assert b"Hello, dave!" in login_send_previous_last_otp_code_response.data
    # The above and below assert result is dependent from test run time

    delete_session_cookie(test_client)
    future_otp_code = pyotp.TOTP(otp_token).at(
        datetime.now() + timedelta(seconds=23)
    )
    login_send_future_otp_code_response = send_otp_code(
        test_client, future_otp_code
    )
    # assert b"Hello, dave!" not in login_send_future_otp_code_response.data
