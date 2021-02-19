from helping import (
    activate_2fa,
    enable_user_2fa,
    refresh_session,
    sign_in_remember,
)


def test_activating_2fa_non_fresh_session_valid_password(
    test_client, init_database
):
    sign_in_remember(
        test_client, "josh_9", "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    test_client.delete_cookie(server_name="localhost", key="session")
    temporary_request = test_client.get("/settings", follow_redirects=True)
    need_refresh_response = activate_2fa(test_client)
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in need_refresh_response.data
    )
    refresh_session(
        test_client, "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    refreshed_session_response = activate_2fa(test_client)
    assert (
        b"You are activating two factor authentication."
        in refreshed_session_response.data
    )
    enable_user_2fa(test_client)
