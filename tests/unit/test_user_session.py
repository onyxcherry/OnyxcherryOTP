from app.models import User


def test_user_change_session_id():
    for _ in range(1000):
        user = User()
        old_session_id = user.sid
        user.revoke_other_sessions()
        new_session_id = user.sid
        assert new_session_id != old_session_id
