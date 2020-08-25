from helping import delete_session_cookie


def test_remember_me_without_2fa_enabled(test_client, init_database):
    login_response = test_client.post(
        "/auth/login",
        data=dict(
            username="josh_9",
            password="m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=",
            remember_me="y",
        ),
        follow_redirects=True,
    )
    assert b"Hello, josh_9" in login_response.data
    delete_session_cookie(test_client)
    index_response = test_client.get("/")
    assert b"Hello, josh_9" in index_response.data
