from unittest.mock import patch

from app.models import User, generate_sid
from app.webauthn.routes import get_current_user_info
from flask import Flask


def test_get_current_user_info_id():
    # Change to namedtuple
    user_database_id = get_current_user_info(None, "20634")
    assert user_database_id[0] == 2


user = User(
    did=7,
    username="thomas",
    sid=generate_sid(),
    email="thomas@gmail.com",
)


def test_get_current_user_info_token():
    app = Flask("bbbb")
    remember_me_to_pass = False
    with app.app_context():
        app.config["TWOFA_SECRET_KEY"] = "ccc"
        token = user.set_valid_credentials(remember_me_to_pass)
        with patch("flask_sqlalchemy._QueryProperty.__get__") as mocked:
            mocked.return_value.filter_by.return_value.first.return_value = (
                user
            )
            database_id, remember_me = get_current_user_info(token, None)
            assert database_id == 7
            assert remember_me is False
