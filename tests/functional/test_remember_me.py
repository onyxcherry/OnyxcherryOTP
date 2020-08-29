from helping import delete_session_cookie, sign_in_remember


def test_remember_me_without_2fa_enabled(test_client, init_database):
    login_response = sign_in_remember(
        test_client, "josh_9", "m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=",
    )
    assert b"Hello, josh_9" in login_response.data
    delete_session_cookie(test_client)
    index_response = test_client.get("/")
    assert b"Hello, josh_9" in index_response.data
