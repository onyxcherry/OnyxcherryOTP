from unittest import mock

from app.models import User
from helping import reset_password_request


@mock.patch("app.auth.routes.send_password_reset_email")
def test_non_existing_user_password_reset_request(
    mocked_send_email, test_client, init_database
):
    response = reset_password_request(
        test_client, "non_existing_email_address@example.com"
    )

    assert (
        b"Check your email for the instructions to reset your password."
        in response.data
    )
    mocked_send_email.assert_not_called()
