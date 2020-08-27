from app.auth.email import send_password_reset_email
from unittest import mock
from base64 import b64encode
from app.models import User
import os
from flask import current_app


@mock.patch("app.auth.email.send_email")
def test_password_reset(mocked_email, test_client, init_database):
    user = User.query.filter_by(email="strawberry8@example.com").first()
    value = b64encode(os.urandom(16)).decode("utf-8")
    token = user.get_reset_password_token(value)
    with current_app.test_request_context():
        send_password_reset_email(user, token)
    mocked_email.assert_called()
