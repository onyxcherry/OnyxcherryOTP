import json

import pyotp
from app.models import User, Webauthn
from fido2 import cbor


def activate_webauthn(test_client):
    activate_webauthn_response = test_client.get(
        "/webauthn/activate", follow_redirects=True
    )
    return activate_webauthn_response


def deactivate_webauthn(test_client):
    deactivate_webauthn_response = test_client.get(
        "/webauthn/deactivate", follow_redirects=True
    )
    return deactivate_webauthn_response


def name_key(test_client, data):
    name_key_response = test_client.post(
        "/webauthn/keys/name", data=data, follow_redirects=True
    )
    return name_key_response


def delete_key(test_client, data):
    delete_key_response = test_client.post(
        "/webauthn/keys/delete", data=data, follow_redirects=True
    )
    return delete_key_response


def enable_user_2fa(test_client):
    generate_token_response = test_client.get("/twofa/generate_token")
    token_data = generate_token_response.get_data()
    jsoned_data = json.loads(token_data)
    otp_token = jsoned_data["secret"]
    otp_code = pyotp.TOTP(otp_token).now()
    data = {"otp_code": otp_code, "csrf_token": "aaabbbccc"}
    check_code_response = test_client.post("/twofa/checkcode", data=data)
    assert b"OK" in check_code_response.data
    assert check_code_response.status_code == 200
    return otp_token


def delete_session_cookie(test_client):
    test_client.delete_cookie(server_name="localhost", key="session")


def send_otp_code(test_client, otp_code):
    send_otp_code_response = test_client.post(
        "/twofa/check_login",
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


def sign_in_no_fr(test_client, username, password):
    sign_in_response = test_client.post(
        "/auth/login",
        data=dict(username=username, password=password),
        follow_redirects=False,
    )
    return sign_in_response


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


def reset_password(test_client, token, new_password):
    response = test_client.post(
        f"/auth/reset_password/{token}",
        data=dict(password=new_password, password2=new_password),
        follow_redirects=True,
    )
    return response


def activate_2fa(test_client):
    response = test_client.get("/twofa/activate", follow_redirects=True)
    return response


def deactivate_2fa(test_client):
    response = test_client.get("/twofa/deactivate", follow_redirects=True)
    return response


def generate_token(test_client):
    response = test_client.get("/twofa/generate_token", follow_redirects=True)
    return response


def reset_password_request(test_client, email):
    response = test_client.post(
        "/auth/reset_password_request",
        data=dict(email=email),
        follow_redirects=True,
    )
    return response


def register(test_client, username, email, password, password2):
    response = test_client.post(
        "/auth/register",
        data=dict(
            username=username,
            email=email,
            password=password,
            password2=password2,
        ),
        follow_redirects=True,
    )
    return response


def get_index(test_client):
    response = test_client.get("/index", follow_redirects=True)
    return response
