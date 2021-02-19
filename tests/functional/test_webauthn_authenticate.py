import uuid
from datetime import datetime
from io import BytesIO

from app.models import Key, User, Webauthn
from conftest import TestConfig
from fido2 import cbor
from helping import sign_in
from soft_webauthn import SoftWebauthnDevice


def test_webauthn_authenticate(test_client, init_database):
    sign_in_response = sign_in(
        test_client, "mark", "c1c149afbf4c8996fb92427ae41e4649b934ca"
    )

    device = SoftWebauthnDevice()
    device.cred_init(TestConfig.RP_ID, uuid.uuid4().hex.encode())
    registered_credential = device.cred_as_attested()

    user4 = User.query.filter_by(username="mark").first()
    webauthn_for_user4 = Webauthn.query.filter_by(user_id=user4.did).first()

    key_created_date = datetime.utcnow()
    key_last_access = datetime.utcnow()
    already_registered_key = Key(
        name="mykey1",
        aaguid=registered_credential.aaguid,
        credential_id=registered_credential.credential_id,
        public_key=cbor.encode(registered_credential.public_key),
        counter=0,
        last_access=key_last_access,
        created=key_created_date,
        user_id=user4.did,
    )

    init_database.session.add(already_registered_key)
    init_database.session.commit()

    pkcro = cbor.decode(test_client.post("/webauthn/authenticate/begin").data)

    assertion = device.get(pkcro, f"https://{TestConfig.RP_ID}")

    assertion_data = cbor.encode(
        {
            "credentialId": assertion["rawId"],
            "clientDataJSON": assertion["response"]["clientDataJSON"],
            "authenticatorData": assertion["response"]["authenticatorData"],
            "signature": assertion["response"]["signature"],
            "userHandle": assertion["response"]["userHandle"],
        }
    )
    raw_response = test_client.post(
        "/webauthn/authenticate/complete",
        input_stream=BytesIO(assertion_data),
        content_type="application/cbor",
    )
    authentication_response = cbor.decode(raw_response.data)

    assert authentication_response == {"status": "OK"}
