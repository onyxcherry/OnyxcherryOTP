import json
from io import BytesIO

from app.models import User, Webauthn
from conftest import TestConfig
from fido2 import cbor
from helping import sign_in
from soft_webauthn import SoftWebauthnDevice


def test_webauthn_register_new_key(test_client, init_database):
    sign_in_response = sign_in(test_client, "dave", "wselfknskjdksdaiujlj")
    device = SoftWebauthnDevice()
    begin_register_response = test_client.post(
        "/webauthn/register/begin", data=json.dumps({"resident": False})
    )
    pkcco = cbor.decode(begin_register_response.data)

    attestation = device.create(pkcco, f"https://{TestConfig.RP_ID}")

    attestation_data = cbor.encode(
        {
            "clientDataJSON": attestation["response"]["clientDataJSON"],
            "attestationObject": attestation["response"]["attestationObject"],
        }
    )
    raw_response = test_client.post(
        "/webauthn/register/complete",
        input_stream=BytesIO(attestation_data),
        content_type="application/cbor",
    )
    registration_response = cbor.decode(raw_response.data)

    assert registration_response == {"status": "OK"}

    user = User.query.filter_by(username="dave").first()
    webauthn = Webauthn.query.filter_by(user_id=user.did).first()

    assert webauthn
    assert webauthn.number == 1
    assert webauthn.is_enabled is False
