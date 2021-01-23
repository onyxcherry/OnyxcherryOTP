from app.models import User, Webauthn
from helping import deactivate_webauthn, delete_session_cookie, sign_in


def test_webauthn_deactivate(test_client, init_database):
    sign_in_response = sign_in(test_client, "oliver", "2398wqshjduiwd8932")

    user = User.query.filter_by(username="oliver").first()
    webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    webauthn.is_enabled = True
    init_database.session.add(webauthn)
    init_database.session.commit()
    got_webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    assert got_webauthn.is_enabled is True

    deactivate_webautn_response = deactivate_webauthn(test_client)

    assert b"Deactivated" in deactivate_webautn_response.data

    webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    assert webauthn.is_enabled is False
