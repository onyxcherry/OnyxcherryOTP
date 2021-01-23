from app.models import User, Webauthn
from helping import activate_webauthn, delete_session_cookie, sign_in


def test_webauthn_activate_enough_keys(test_client, init_database):
    delete_session_cookie(test_client)
    sign_in_response = sign_in(test_client, "anna", "ukehjwqbjhwqkbejw")
    activate_webautn_response = activate_webauthn(test_client)

    assert b"Enabled" in activate_webautn_response.data

    user = User.query.filter_by(username="anna").first()
    webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    assert webauthn.is_enabled is True


def test_webauthn_activate_not_enough_keys(test_client, init_database):
    delete_session_cookie(test_client)
    sign_in_response = sign_in(test_client, "thomas", "qghjoiwjiklwek")
    activate_webautn_response = activate_webauthn(test_client)
    assert b"register" in activate_webautn_response.data

    user = User.query.filter_by(username="thomas").first()
    webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    assert webauthn.is_enabled is False
