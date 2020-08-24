from unittest import mock

from app.models import User


@mock.patch("app.auth.routes.send_password_reset_email")
def test_limited_password_reset_requests(
    mocked_email, test_client, init_database
):
    tests_count = 7
    message = b"Check your email for the instructions to reset your password."
    for _ in range(tests_count):
        response = test_client.post(
            "/auth/reset_password_request",
            data=dict(email="strawberry8@example.com"),
            follow_redirects=True,
        )
        assert message in response.data

    response = test_client.post(
        "/auth/reset_password_request",
        data=dict(email="strawberry8@example.com"),
        follow_redirects=True,
    )
    assert message in response.data
    mocked_email.assert_called()
    assert mocked_email.call_count == 2
