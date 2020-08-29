import os
from base64 import b64encode
from datetime import datetime

from app.models import ResetPassword, User
from helping import reset_password


def test_changing_password_with_jwt(test_client, init_database):
    user = User.query.filter_by(username="straw_berry").first()
    value = b64encode(os.urandom(16)).decode("utf-8")
    token = user.get_reset_password_token(value)
    db_date = datetime.utcnow()
    reset_password_new = ResetPassword(
        first_value=value, first_date=db_date, user_id=user.id
    )
    init_database.session.add(reset_password_new)
    init_database.session.commit()
    new_password = "aabbccdd"
    response = reset_password(test_client, token, new_password)
    assert b"Your password has been reset." in response.data
    assert user.check_password(new_password)
    assert not user.check_password("EJew@MHHQ7x-g.4<")
