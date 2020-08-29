from helping import (
    activate_2fa,
    generate_token,
    refresh_session_fr,
    sign_in_remember,
)


def test_activating_2fa_non_fresh_session_invalid_password(
    test_client, init_database
):
    sign_in_remember(
        test_client, "josh_9", "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    test_client.delete_cookie(server_name="localhost", key="session")
    temporary_request = test_client.get("/settings", follow_redirects=True)
    refresh_response = activate_2fa(test_client)
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in refresh_response.data
    )
    refreshing_password_response = refresh_session_fr(
        test_client, "invalid_password_asdkbnsajkhdbcaJSNDXMNSAaklrnkjfndsakj"
    )
    assert b"Invalid password" in refreshing_password_response.data

    generate_token_response = generate_token(test_client)
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in generate_token_response.data
    )
