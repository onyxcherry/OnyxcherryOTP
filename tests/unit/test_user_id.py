from app.models import User


def test_database_id():
    user_id_from_cookie = "20658"
    assert User.get_database_id(user_id_from_cookie) == 2


def test_session_id():
    user_id_from_cookie = "20658"
    assert User.get_session_id(user_id_from_cookie) == 658


def test_padded_id():
    assert User.get_padded_session_id_str(12) == "0012"
