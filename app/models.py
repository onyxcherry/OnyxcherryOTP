from datetime import datetime
from time import time

import jwt
import pyotp
from flask import current_app
from flask_login import UserMixin

from app import bcrypt, db, login


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    otp = db.relationship('OTP', backref='user', uselist=False)

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password, 13)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def set_valid_credentials(self, expires_in=60):
        return jwt.encode({'twofa_login': self.username, 'exp': time() + expires_in},
        current_app.config['TWOFA_SECRET_KEY'], algorithm='HS256').decode('utf-8')
    
    @staticmethod
    def verify_valid_credentials(token):
        try:
            user_id = jwt.decode(token, current_app.config['TWOFA_SECRET_KEY'],
            algorithms=['HS256'])['twofa_login']
        except:
            return
        return OTP.query.get(user_id)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)


class OTP(db.Model):
    __tablename__ = "otp"
    id = db.Column(db.Integer, primary_key=True)
    secret = db.Column(db.String(32))
    is_valid = db.Column(db.Integer, default=0) # change to d.Boolean if database supports booleans
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return f'<OTP {self.secret}>'


@login.user_loader
def load_user(id):
    return User.query.get(int(id))