from unittest import mock

from helping import reset_password_request


@mock.patch("app.auth.routes.send_password_reset_email")
def test_limited_password_reset_requests(
    mocked_email, test_client, init_database
):
    tests_count = 7
    email = "strawberry8@example.com"
    message = b"Check your email for the instructions to reset your password."
    for _ in range(tests_count):
        response = reset_password_request(test_client, email)
        assert message in response.data

    response = reset_password_request(test_client, email)
    assert message in response.data
    mocked_email.assert_called()
    assert mocked_email.call_count == 2
