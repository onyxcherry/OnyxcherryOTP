import os
from base64 import b64encode
from datetime import datetime
from app.models import User, ResetPasswordValue


def test_changing_password_with_jwt(test_client, init_database):
    username = "straw_berry"
    user = User.query.filter_by(username="straw_berry").first()
    value = b64encode(os.urandom(16)).decode("utf-8")
    token = user.get_reset_password_token(value)
    db_date = datetime.utcnow()
    reset_password_new = ResetPasswordValue(
        first_value=value, first_date=db_date, user_id=user.id
    )
    init_database.session.add(reset_password_new)
    init_database.session.commit()
    new_password = "aabbccdd"
    response = test_client.post(
        f"/auth/reset_password/{token}",
        data=dict(password=new_password, password2=new_password),
        follow_redirects=True,
    )

    assert b"Your password has been reset." in response.data
    assert user.check_password(new_password)
    assert not user.check_password("EJew@MHHQ7x-g.4<")
