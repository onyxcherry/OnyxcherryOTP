def test_register_and_login(test_client, init_database):
    register_response = test_client.post(
        "/auth/register",
        data=dict(
            username="bob",
            email="bob@example.eu",
            password="bob_roccat867",
            password2="bob_roccat867",
        ),
        follow_redirects=True,
    )

    assert (
        b"Congratulations, you are now a registered user!"
        in register_response.data
    )

    login_response = test_client.post(
        "/auth/login",
        data=dict(username="bob", password="bob_roccat867"),
        follow_redirects=True,
    )
    assert b"Hello, bob" in login_response.data
    assert b"Invalid username or password" not in login_response.data
