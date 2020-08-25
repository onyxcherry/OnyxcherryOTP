from helping import sign_in_remember, refresh_session_fr


def test_activating_2fa_non_fresh_session_invalid_password(
    test_client, init_database
):
    _ = sign_in_remember(
        test_client, "josh_9", "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM="
    )
    test_client.delete_cookie(server_name="localhost", key="session")
    temporary_request = test_client.get("/settings", follow_redirects=True)
    refresh_response = test_client.get(
        "/auth/activate_2fa", follow_redirects=True
    )
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in refresh_response.data
    )
    refreshing_password_response = refresh_session_fr(
        test_client, "invalid_password_asdkbnsajkhdbcaJSNDXMNSAaklrnkjfndsakj"
    )
    assert b"Invalid password" in refreshing_password_response.data

    generate_token_response = test_client.get(
        "/auth/generate_token", follow_redirects=True
    )
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in generate_token_response.data
    )
