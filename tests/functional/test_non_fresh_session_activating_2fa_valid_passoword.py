import json
import pyotp

def test_not_fresh_session_activating_2fa(test_client, init_database):
    login_response = test_client.post(
        "/auth/login",
        data=dict(
            username="josh_9",
            password="m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=",
            remember_me="y",
        ),
        follow_redirects=False,
    )
    test_client.delete_cookie(server_name="localhost", key="session")
    temporary_request = test_client.get("/settings", follow_redirects=True)
    need_refresh_response = test_client.get("/auth/activate_2fa", follow_redirects=True)
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in need_refresh_response.data
    )
    refreshing_password_response = test_client.post(
        "/auth/refresh",
        data=dict(password="m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="),
    )
    refreshed_session_response = test_client.get(
        "/auth/activate_2fa", follow_redirects=True
    )
    assert (
        b"You are activating two factor authentication."
        in refreshed_session_response.data
    )

    generate_token_response = test_client.get('/auth/generate_token')
    token_data = generate_token_response.get_data()
    jsoned_data = json.loads(token_data)
    token = jsoned_data['secret']
    otp_code = pyotp.TOTP(token).now()
    check_code_response = test_client.post('/auth/checkcode', data=otp_code)
    assert b'OK' in check_code_response.data
    assert check_code_response.status_code == 200