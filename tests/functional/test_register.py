from unittest import mock

from helping import register


@mock.patch("app.auth.routes.User")
def test_taken_nickname(mocked_user, test_client, init_database):
    response = register(
        test_client, "straw_berry", "josh@example.com", "aabbccdd", "aabbccdd",
    )
    mocked_user.assert_not_called()
    assert b"Please use a different username." in response.data


@mock.patch("app.auth.routes.User")
def test_taken_email(mocked_user, test_client, init_database):
    response = register(
        test_client,
        "anything",
        "strawberry8@example.com",
        "aabbccdd",
        "aabbccdd",
    )
    mocked_user.assert_not_called()
    assert b"Please use a different email address." in response.data


@mock.patch("app.auth.routes.User")
def test_short_password(mocked_user, test_client, init_database):
    response = register(
        test_client,
        "anything",
        email="josh@example.com",
        password="j",
        password2="j",
    )
    mocked_user.assert_not_called()
    assert b"Field must be" in response.data
    assert b"8" in response.data


@mock.patch("app.auth.routes.User")
def test_not_equal_passwords(mocked_user, test_client, init_database):
    response = register(
        test_client, "anything", "josh@example.com", "jjjjjjjj", "kkkkkkkk",
    )
    mocked_user.assert_not_called()
    assert b"Passwords must match" in response.data


@mock.patch("app.auth.routes.User")
def test_case_insensitive_email(mocked_user, test_client, init_database):
    response = register(
        test_client,
        username="indeed_not_existing_sdkljfuhnbswkjdnqjwenjkndxuzx",
        email="daVe16@outlook.com",
        password="somethingsecure",
        password2="somethingsecure",
    )
    mocked_user.assert_not_called()
    assert b"Please use a different email address." in response.data
