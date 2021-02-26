from io import BytesIO

from app.models import Key, User, Webauthn
from conftest import KeyList, TestConfig
from fido2 import cbor
from fido2.cose import ES256
from helping import sign_in
from soft_webauthn import SoftWebauthnDevice


def test_webauthn_authenticate(test_client, init_database):
    sign_in_response = sign_in(
        test_client, "jennie", "9df1c362e4df3e51edd1acde9"
    )

    device = SoftWebauthnDevice()
    user = User.query.filter_by(username="jennie").first()
    webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    user_handle = webauthn.user_identifier

    device.cred_init(TestConfig.RP_ID, user_handle)

    device.private_key = KeyList.priv_one

    user5_first_security_key_public_key = ES256.from_cryptography_key(
        device.private_key.public_key()
    )
    key = (
        Key.query.filter_by(user_id=user.did)
        .filter_by(public_key=cbor.encode(user5_first_security_key_public_key))
        .first()
    )
    device.credential_id = key.credential_id

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

    settings_response = test_client.get("/settings")
    assert settings_response.status_code == 200
