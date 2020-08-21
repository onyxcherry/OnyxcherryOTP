def test_remember_me_without_2fa_enabled(test_client, init_database):
    response = test_client.post(
        "/auth/login",
        data=dict(
            username="josh_9",
            password="m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=",
            remember_me="y",
        ),
        follow_redirects=False,
    )

    remember_me_header = response.headers.get("Set-cookie")
    assert remember_me_header.find("remember_token") != -1
    assert remember_me_header.find("HttpOnly") != -1
    assert remember_me_header.find("Path=/") != -1
    assert remember_me_header.find("SameSite=Strict") != -1
