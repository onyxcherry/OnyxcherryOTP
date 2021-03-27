import re
from unittest import mock

from app.models import User
from helping import reset_password, reset_password_request


@mock.patch("app.auth.email.send_email")
def test_changing_password_with_jwt(
    mocked_email, test_client, init_database, flush_redis
):
    resp = reset_password_request(test_client, "strawberry8@example.com")
    mocked_email.assert_called()

    user = User.query.filter_by(email="strawberry8@example.com").first()
    assert not user.check_password("myVerL0ngnewpassword".encode())

    regex = r"https?://[a-zA-Z0-9.]+/auth/reset_password/([a-zA-Z0-9._-]+)"
    url = re.findall(regex, str(mocked_email.call_args_list[0]))
    email_secret_token = re.search(
        regex, str(mocked_email.call_args_list[0])
    ).groups()[0]
    pass_reset_resp = reset_password(
        test_client, email_secret_token, "myVerL0ngnewpassword"
    )
    assert b"Your password has been reset." in pass_reset_resp.data
    assert user.check_password("myVerL0ngnewpassword".encode())
