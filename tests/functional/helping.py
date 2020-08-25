import pyotp
import json


def enable_user_2fa(test_client):
    generate_token_response = test_client.get("/auth/generate_token")
    token_data = generate_token_response.get_data()
    jsoned_data = json.loads(token_data)
    otp_token = jsoned_data["secret"]
    otp_code = pyotp.TOTP(otp_token).now()
    check_code_response = test_client.post("/auth/checkcode", data=otp_code)
    assert b"OK" in check_code_response.data
    assert check_code_response.status_code == 200
    return otp_token


def delete_session_cookie(test_client):
    test_client.delete_cookie(server_name="localhost", key="session")


def send_otp_code(test_client, otp_code):
    send_otp_code_response = test_client.post(
        "/auth/check_2fa_login",
        data=dict(otp_code=otp_code),
        follow_redirects=True,
    )
    return send_otp_code_response


def sign_in(test_client, username, password):
    sign_in_response = test_client.post(
        "/auth/login",
        data=dict(username=username, password=password),
        follow_redirects=True,
    )
    return sign_in_response


def sign_in_remember(test_client, username, password):
    sign_in_with_remember_response = test_client.post(
        "/auth/login",
        data=dict(username=username, password=password, remember_me="y"),
        follow_redirects=True,
    )
    return sign_in_with_remember_response


def refresh_session(test_client, password):
    refresh_password_response = test_client.post(
        "/auth/refresh", data=dict(password=password),
    )
    return refresh_password_response


def refresh_session_fr(test_client, password):
    refresh_session_response = test_client.post(
        "/auth/refresh", data=dict(password=password), follow_redirects=True,
    )
    return refresh_session_response
