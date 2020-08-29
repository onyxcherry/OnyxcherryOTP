import os
from base64 import b64encode
from datetime import datetime, timedelta
from time import time
from typing import Tuple

import jwt
from app import bcrypt, db, login
from flask import current_app
from flask_login import UserMixin


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    otp = db.relationship("OTP", backref="user", uselist=False)
    reset_password_value = db.relationship(
        "ResetPassword", backref="user", uselist=False
    )

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(
            password, 13
        ).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_valid_credentials(self, remember_me, expires_in=60):
        return jwt.encode(
            {
                "twofa_login": self.username,
                "remember_me": remember_me,
                "exp": time() + expires_in,
            },
            current_app.config["TWOFA_SECRET_KEY"],
            algorithm="HS256",
        ).decode("utf-8")

    def get_reset_password_token(self, value, expires_in=600):
        return jwt.encode(
            {
                "reset_password": self.username,
                "value": value,
                "exp": time() + expires_in,
            },
            current_app.config["SECRET_KEY"],
            algorithm="HS256",
        ).decode("utf-8")

    @staticmethod
    def get_random_base64_value():
        return b64encode(os.urandom(16)).decode("utf-8")

    @staticmethod
    def delete_expired_tokens(reset_password: object):
        now_compare_time = datetime.utcnow() - timedelta(seconds=600)
        if (
            reset_password.first_date
            and reset_password.first_date < now_compare_time
        ):
            reset_password.first_value = None
            reset_password.first_date = None
            db.session.add(reset_password)
            db.session.commit()
        if (
            reset_password.second_date
            and reset_password.second_date < now_compare_time
        ):
            reset_password.second_value = None
            reset_password.second_date = None
            db.session.add(reset_password)
            db.session.commit()
        return

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
    is_valid = db.Column(
        db.Boolean, default=False
    )  # change to db.Boolean if database supports booleans
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    remaining_attempts = db.Column(db.Integer)

    def __repr__(self):
        return f"<OTP {self.secret}>"


class ResetPassword(db.Model):
    __tablename__ = "reset_password"
    id = db.Column(db.Integer, primary_key=True)
    first_value = db.Column(db.String(32))
    first_date = db.Column(db.DateTime)
    second_value = db.Column(db.String(32))
    second_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<ResetPasswordValue for user {self.user_id}>"


@login.user_loader
def load_user(id):
    return User.query.get(int(id))
