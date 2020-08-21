def test_taken_nickname(test_client, init_database):
    response = test_client.post(
        "/auth/register",
        data=dict(
            username="straw_berry",
            email="josh@example.com",
            password="aabbccdd",
            password2="aabbccdd",
        ),
    )
    assert b"Please use a different username." in response.data


def test_taken_email(test_client, init_database):
    response = test_client.post(
        "/auth/register",
        data=dict(
            username="anything",
            email="strawberry8@example.com",
            password="aabbccdd",
            password2="aabbccdd",
        ),
    )
    assert b"Please use a different email address." in response.data


def test_short_password(test_client, init_database):
    response = test_client.post(
        "/auth/register",
        data=dict(
            username="anything", email="josh@example.com", password="j", password2="j",
        ),
    )
    assert b"Field must be" in response.data
    assert b"8" in response.data


def test_not_equal_passwords(test_client, init_database):
    response = test_client.post(
        "/auth/register",
        data=dict(
            username="anything",
            email="josh@example.com",
            password="jjjjjjjj",
            password2="kkkkkkkk",
        ),
    )
    assert b"Field must be equal" in response.data


def test_login_taken_username(test_client, init_database):
    response = test_client.post(
        "/auth/login",
        data=dict(username="straw_berry", password="aabbccdd"),
        follow_redirects=True,
    )
    assert b"Invalid username or password" in response.data

