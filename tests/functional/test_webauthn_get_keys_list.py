import binascii
import json

from app.models import Key, User
from helping import get_keys_list, sign_in


def test_webauthn_get_keys_list(test_client, init_database):
    sign_in_response = sign_in(test_client, "oliver", "2398wqshjduiwd8932")
    user = User.query.filter_by(username="oliver").first()

    keys_list_response = get_keys_list(test_client)
    keys_list = keys_list_response.data

    parsed_keys_list = json.loads(keys_list)
    first_key_credential_id_hex = list(parsed_keys_list)[0]
    first_key = (
        Key.query.filter_by(user_id=user.did)
        .filter_by(credential_id=binascii.a2b_hex(first_key_credential_id_hex))
        .first()
    )
    assert first_key is not None
    assert parsed_keys_list[first_key_credential_id_hex]["name"] is not None
    assert (
        parsed_keys_list[first_key_credential_id_hex]["last_access"]
        is not None
    )
