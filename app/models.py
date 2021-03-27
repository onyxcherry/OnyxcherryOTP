import binascii
import os
from base64 import b64encode
from random import SystemRandom
from time import time
from typing import Tuple

import bcrypt
import jwt
from app import db, login
from flask import current_app
from flask_login import UserMixin


def generate_sid() -> int:
    cryptogen = SystemRandom()
    return cryptogen.randrange(9999)


class User(UserMixin, db.Model):
    # __abstract__ = True
    def __init__(self, *args, **kwargs):
        self.sid = generate_sid()
        super().__init__(*args, **kwargs)

    did = db.Column(db.Integer, primary_key=True)
    sid = db.Column(db.Integer)
    username = db.Column(db.String(64), index=True, unique=True)
    # See [https://www.rfc-editor.org/errata_search.php?rfc=3696&eid=1003]
    email = db.Column(db.String(256), index=True, unique=True)
    # Bcrypt ignores bytes beyond 72th but it isn't necessary to inform about
    password_hash = db.Column(db.String(128))
    otp = db.relationship("OTP", backref="user", uselist=False)
    webauthn = db.relationship("Webauthn", backref="user", uselist=False)
    key = db.relationship("Key", backref="user")

    def __repr__(self):
        return f"<User {self.username}>"

    def change_session_id(self):
        last_session_id = self.sid
        while True:
            # check if session id differs from the latest
            new_session_id = generate_sid()
            if new_session_id != last_session_id:
                break
        self.sid = new_session_id

    def revoke_other_sessions(self):
        self.change_session_id()

    @staticmethod
    def get_database_id(user_id: str) -> int:
        assert isinstance(user_id, str)
        database_id_str = user_id[:-4]
        database_id = int(database_id_str)
        assert isinstance(database_id, int)
        return database_id

    @staticmethod
    def get_session_id(user_id: str) -> int:
        assert isinstance(user_id, str)
        session_id_str = user_id[-4:]
        assert len(session_id_str) == 4
        session_id = int(session_id_str)
        assert isinstance(session_id, int)
        return session_id

    @staticmethod
    def get_padded_session_id_str(session_id: int) -> str:
        assert isinstance(session_id, int)
        padded_session_id_str = str(session_id).zfill(4)
        assert len(padded_session_id_str) == 4
        return padded_session_id_str

    def get_id(self) -> str:
        assert isinstance(self.did, int)
        assert isinstance(self.sid, int)
        padded_sid = self.get_padded_session_id_str(self.sid)
        assert len(padded_sid) == 4
        return_value = f"{self.did}{padded_sid}"
        return return_value

    def set_password(self, password: bytes):
        # do not explicit pass Bcrypt log rounds -
        # instead specify that in BCRYPT_LOG_ROUNDS environment
        salt = bcrypt.gensalt(
            rounds=current_app.config.get("BCRYPT_LOG_ROUNDS")
        )
        if isinstance(password, str):
            password = password.encode()
        self.password_hash = bcrypt.hashpw(password, salt)

    def check_password(self, password: bytes):
        if isinstance(password, str):
            password = password.encode()
        return bcrypt.checkpw(password, self.password_hash)

    def set_valid_credentials(self, remember_me, expires_in=60):
        return jwt.encode(
            {
                "twofa_login": self.username,
                "remember_me": remember_me,
                "exp": time() + expires_in,
            },
            current_app.config["TWOFA_SECRET_KEY"],
            algorithm="HS256",
        )

    def get_reset_password_token(self, value, expires_in=600):
        return jwt.encode(
            {
                "reset_password": self.username,
                "value": value,
                "exp": time() + expires_in,
            },
            current_app.config["SECRET_KEY"],
            algorithm="HS256",
        )

    @staticmethod
    def get_random_base64_value():
        return b64encode(os.urandom(16)).decode("utf-8")

    @staticmethod
    def verify_reset_password_token(token: str) -> Tuple[str, str]:
        try:
            jwt_decoded = jwt.decode(
                token, current_app.config["SECRET_KEY"], algorithms=["HS256"]
            )
            username = jwt_decoded["reset_password"]
            value = jwt_decoded["value"]
        except (
            jwt.exceptions.InvalidSignatureError,
            jwt.exceptions.ExpiredSignatureError,
        ):
            return
        return (username, value)

    @staticmethod
    def verify_twofa_login_token(token: bytes) -> Tuple[str, str]:
        try:
            jwt_decoded = jwt.decode(
                token,
                current_app.config["TWOFA_SECRET_KEY"],
                algorithms=["HS256"],
            )
            username = jwt_decoded["twofa_login"]
            remember_me = jwt_decoded["remember_me"]
        except (
            jwt.exceptions.InvalidSignatureError,
            jwt.exceptions.ExpiredSignatureError,
        ):
            return None
        return (username, remember_me)


class OTP(db.Model):
    __tablename__ = "otp"
    id = db.Column(db.Integer, primary_key=True)
    secret = db.Column(db.String(32))
    is_valid = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.did"))
    remaining_attempts = db.Column(db.Integer)

    def __repr__(self):
        return f"<OTP {self.secret}>"


class Webauthn(db.Model):
    __tablename__ = "webauthn"
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.Integer, default=0)
    is_enabled = db.Column(db.Boolean, default=False)
    user_identifier = db.Column(db.LargeBinary(64))
    user_id = db.Column(db.Integer, db.ForeignKey("user.did"))

    def __repr__(self):
        return f"<Webauthn - {self.number} keys for user {self.user_id}>"


class Key(db.Model):
    __tablename__ = "keys"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    aaguid = db.Column(db.LargeBinary(16))
    credential_id = db.Column(db.LargeBinary(64))
    client_data_hash = db.Column(db.LargeBinary(32))
    public_key = db.Column(db.LargeBinary(77))
    counter = db.Column(db.Integer, default=0)
    attestation = db.Column(db.LargeBinary(1021))
    info = db.Column(db.String(1000))
    is_resident = db.Column(db.Boolean(), default=False)
    last_access = db.Column(db.DateTime)
    created = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey("user.did"))

    def __repr__(self):
        short_hex_cred_id = binascii.b2a_hex(self.credential_id)[:6].decode()
        return f"<Key - {self.name} for {short_hex_cred_id}>"


@login.user_loader
def load_user(user_id):
    assert isinstance(user_id, str)
    did = User.get_database_id(user_id)
    sid = User.get_session_id(user_id)
    user = User.query.filter_by(did=did).first()
    # Very important check
    if user.sid == sid:
        return user
    return None
