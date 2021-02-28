import hashlib
import os
from datetime import datetime

import pytest
from app import Config, create_app, db
from app.models import Key, User, Webauthn
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, cbor
from soft_webauthn import SoftWebauthnDevice


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    WTF_CSRF_METHODS = []
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    BCRYPT_LOG_ROUNDS = 4
    SECRET_KEY = "s2yvxuwZ7Ipf5JKv6uV7y85AfJJdhhSPq65bKZtH7l4="
    TWOFA_SECRET_KEY = "cryG2D0C95mlO9r/rnple7FOdQhYsPL8boXB/qOXuPM="


class KeyList:
    pass


@pytest.fixture(scope="session")
def user():
    user = User(username="paul", email="paul@example.com")
    return user


@pytest.fixture(scope="module")
def test_client():
    onyxcherry_otp = create_app(TestConfig)

    testing_client = onyxcherry_otp.test_client()

    app_context = onyxcherry_otp.app_context()
    app_context.push()

    yield testing_client

    app_context.pop()


@pytest.fixture(scope="module")
def init_database():

    db.create_all()

    user1 = User(username="straw_berry", email="strawberry8@example.com")
    user1.set_password("EJew@MHHQ7x-g.4<")
    user2 = User(username="josh_9", email="josh+otpapp@gmail.com")
    user2.set_password("m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=")
    user3 = User(username="dave", email="dave16@outlook.com")
    user3.set_password("wselfknskjdksdaiujlj")
    db.session.add(user1)
    db.session.add(user2)
    db.session.add(user3)

    user4 = User(username="mark", email="mark@gmail.com")
    user4.set_password("c1c149afbf4c8996fb92427ae41e4649b934ca")

    user5 = User(username="jennie", email="jennie@gmail.com")
    user5.set_password("9df1c362e4df3e51edd1acde9")

    user6 = User(username="anna", email="anna@gmail.com")
    user6.set_password("ukehjwqbjhwqkbejw")

    user7 = User(username="thomas", email="thomas@gmail.com")
    user7.set_password("qghjoiwjiklwek")

    user8 = User(username="oliver", email="oliver@gmail.com")
    user8.set_password("2398wqshjduiwd8932")

    db.session.add(user4)
    db.session.add(user5)
    db.session.add(user6)
    db.session.add(user7)
    db.session.add(user8)
    db.session.commit()

    got_user4 = User.query.filter_by(username="mark").first()
    webauthn_for_user4 = Webauthn(
        number=0, is_enabled=True, user_id=got_user4.did
    )

    got_user5 = User.query.filter_by(username="jennie").first()
    webauthn_for_user5 = Webauthn(
        number=1,
        is_enabled=True,
        user_identifier=b"\x7e" + os.urandom(31),
        user_id=got_user5.did,
    )

    device = SoftWebauthnDevice()

    pkcco = cbor.decode(
        cbor.encode(
            {
                "publicKey": {
                    "rp": {"id": TestConfig.RP_ID, "name": "Demo server"},
                    "user": {
                        "id": webauthn_for_user5.user_identifier,
                        "icon": "https://example.com/image.png",
                        "name": got_user5.username,
                        "displayName": f"Tests - {got_user5.username}",
                    },
                    "timeout": 30000,
                    "challenge": (
                        b"\xcc\x8e\x03\x04\xdb6bd\xa0d\x98\xa9Vz0p.x"
                        b"\xa4\xf5\xd4\xf6%\xf8\x86zt\x1d\ny\xf9<"
                    ),
                    "pubKeyCredParams": [
                        {"alg": -7, "type": "public-key"},
                        {"alg": -8, "type": "public-key"},
                        {"alg": -37, "type": "public-key"},
                        {"alg": -257, "type": "public-key"},
                    ],
                    "excludeCredentials": [],
                    "authenticatorSelection": {
                        "userVerification": "discouraged",
                        "authenticatorAttachment": "cross-platform",
                    },
                }
            }
        )
    )
    attestation = device.create(pkcco, f"https://{TestConfig.RP_ID}")
    KeyList.priv_one = device.private_key

    att_obj = AttestationObject(attestation["response"]["attestationObject"])

    client_data = ClientData(attestation["response"]["clientDataJSON"])

    auth_data = att_obj.auth_data

    key_for_user5 = Key(
        name="Key 1",
        aaguid=auth_data.credential_data.aaguid,
        credential_id=auth_data.credential_data.credential_id,
        client_data_hash=hashlib.sha256(client_data).digest(),
        public_key=cbor.encode(auth_data.credential_data.public_key),
        counter=att_obj.auth_data.counter,
        attestation=attestation["response"]["attestationObject"],
        info="TODO",
        last_access=datetime.utcnow(),
        created=datetime.utcnow(),
        user_id=got_user5.did,
    )

    db.session.add(webauthn_for_user4)
    db.session.add(webauthn_for_user5)
    db.session.add(key_for_user5)

    # Users for activating Webauthn
    got_user6 = User.query.filter_by(username="anna").first()
    webauthn_for_user6 = Webauthn(
        number=2, is_enabled=False, user_id=got_user6.did
    )

    got_user7 = User.query.filter_by(username="thomas").first()
    webauthn_for_user7 = Webauthn(
        number=1, is_enabled=False, user_id=got_user7.did
    )
    db.session.add(webauthn_for_user6)
    db.session.add(webauthn_for_user7)

    got_user8 = User.query.filter_by(username="oliver").first()
    webauthn_for_user8 = Webauthn(
        number=1, is_enabled=False, user_id=got_user8.did
    )
    first_key_for_user8 = Key(
        name="Key 1",
        aaguid=b"",
        credential_id=b"againnotrealbutrequiredtolistkeyproperly",
        client_data_hash=hashlib.sha256(b"a").digest(),
        public_key=b"",
        counter=0,
        attestation=b"",
        info="TODO",
        last_access=datetime.utcnow(),
        created=datetime.utcnow(),
        user_id=got_user8.did,
    )
    second_key_for_user8 = Key(
        name="Key 2",
        aaguid=b"",
        credential_id=b"notrealbutnecessarytodelete",
        client_data_hash=hashlib.sha256(b"a").digest(),
        public_key=b"",
        counter=0,
        attestation=b"",
        info="TODO",
        last_access=datetime.utcnow(),
        created=datetime.utcnow(),
        user_id=got_user8.did,
    )
    db.session.add(webauthn_for_user8)
    db.session.add(first_key_for_user8)
    db.session.add(second_key_for_user8)

    db.session.commit()

    yield db

    db.drop_all()
