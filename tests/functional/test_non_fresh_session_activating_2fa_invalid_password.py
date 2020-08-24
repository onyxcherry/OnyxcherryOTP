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
    refresh_response = test_client.get(
        "/auth/activate_2fa", follow_redirects=True
    )
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in refresh_response.data
    )
    refreshing_password_response = test_client.post(
        "/auth/refresh",
        data=dict(
            password="invalid_password_asdkbnsajkhdbcaJSNDX,MNSAaklrnkjfndsakj"
        ),
        follow_redirects=True,
    )
    assert b"Invalid password" in refreshing_password_response.data

    generate_token_response = test_client.get(
        "/auth/generate_token", follow_redirects=True
    )
    assert (
        b"To protect your account, please reauthenticate to access this page."
        in generate_token_response.data
    )
