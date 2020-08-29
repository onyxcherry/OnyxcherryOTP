from helping import register, sign_in


def test_register_and_login(test_client, init_database):
    register_response = register(
        test_client, "bob", "bob@example.eu", "bob_roccat867", "bob_roccat867",
    )
    assert (
        b"Congratulations, you are now a registered user!"
        in register_response.data
    )

    sign_in_response = sign_in(test_client, "bob", "bob_roccat867")
    assert b"Hello, bob" in sign_in_response.data
    assert b"Invalid username or password" not in sign_in_response.data
