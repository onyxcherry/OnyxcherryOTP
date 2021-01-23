import binascii

from app.models import Key, User
from helping import delete_key, sign_in


def test_webauthn_delete_key(test_client, init_database):
    sign_in_response = sign_in(test_client, "oliver", "2398wqshjduiwd8932")
    user = User.query.filter_by(username="oliver").first()
    key = (
        Key.query.filter_by(user_id=user.did).filter_by(
            credential_id="notrealbutnecessarytodelete".encode()
        )
    ).first()

    assert key is not None

    delete_key_response = delete_key(
        test_client,
        data={
            "credential_id": binascii.b2a_hex(key.credential_id),
            "key_name": "MyKey with spaces",
        },
    )

    key = (
        Key.query.filter_by(user_id=user.did)
        .filter_by(
            credential_id=binascii.b2a_hex(b"notrealbutnecessarytodelete")
        )
        .first()
    )
    assert key is None
