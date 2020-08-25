import json
import pyotp

from helping import sign_in_remember, refresh_session, enable_user_2fa


def test_activating_2fa_non_fresh_session_valid_password(
    test_client, init_database
):
    _ = sign_in_remember(
        test_client, "josh_9", "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    test_client.delete_cookie(server_name="localhost", key="session")
    temporary_request = test_client.get("/settings", follow_redirects=True)
    need_refresh_response = test_client.get(
        "/auth/activate_2fa", follow_redirects=True
    )
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in need_refresh_response.data
    )
    _ = refresh_session(
        test_client, "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    refreshed_session_response = test_client.get(
        "/auth/activate_2fa", follow_redirects=True
    )
    assert (
        b"You are activating two factor authentication."
        in refreshed_session_response.data
    )
    _ = enable_user_2fa(test_client)
