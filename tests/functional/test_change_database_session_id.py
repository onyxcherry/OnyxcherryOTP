from app.models import User, change_session_id


def test_change_session_id_in_database(test_client, init_database):
    user = User.query.filter_by(username="dave").first()
    old_session_id = user.sid
    change_session_id(user)
    new_session_id = user.sid
    assert new_session_id != old_session_id
