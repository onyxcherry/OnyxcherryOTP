import os
from base64 import b64encode
from app.models import User


def test_reset_password_requests_token(test_client, init_database):
    username = "straw_berry"
    user = User(username=username)
    value = b64encode(os.urandom(16)).decode("utf-8")
    token = user.get_reset_password_token(value)
    user_instance, _ = user.verify_reset_password_token(token)
    assert user_instance.username == username
