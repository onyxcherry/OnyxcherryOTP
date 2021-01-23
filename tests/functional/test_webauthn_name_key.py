import binascii

from app.models import Key, User
from helping import name_key, sign_in


def test_webauthn_name_key(test_client, init_database):
    sign_in_response = sign_in(test_client, "oliver", "2398wqshjduiwd8932")
    user = User.query.filter_by(username="oliver").first()
    # It doesn't matter name of which key we will change
    key = Key.query.filter_by(user_id=user.did).first()

    assert key.name == "Key 1"

    name_key_response = name_key(
        test_client,
        data={
            "credential_id": binascii.b2a_hex(key.credential_id),
            "key_name": "MyKey with spaces",
        },
    )

    key = Key.query.filter_by(user_id=user.did).first()
    assert key.name == "MyKey with spaces"
