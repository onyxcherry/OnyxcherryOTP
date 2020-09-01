from helping import register


def test_taken_nickname(test_client, init_database):
    response = register(
        test_client, "straw_berry", "josh@example.com", "aabbccdd", "aabbccdd",
    )
    assert b"Please use a different username." in response.data


def test_taken_email(test_client, init_database):

    response = register(
        test_client,
        "anything",
        "strawberry8@example.com",
        "aabbccdd",
        "aabbccdd",
    )
    assert b"Please use a different email address." in response.data


def test_short_password(test_client, init_database):
    response = register(
        test_client,
        "anything",
        email="josh@example.com",
        password="j",
        password2="j",
    )
    assert b"Field must be" in response.data
    assert b"8" in response.data


def test_not_equal_passwords(test_client, init_database):
    response = register(
        test_client, "anything", "josh@example.com", "jjjjjjjj", "kkkkkkkk",
    )
    assert b"Passwords must match" in response.data
