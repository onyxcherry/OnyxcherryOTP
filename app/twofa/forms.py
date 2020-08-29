from app.models import User
from flask_babel import _
from flask_babel import lazy_gettext as _l
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    ValidationError,
)


class CheckOTPCode(FlaskForm):
    password = StringField(_l("Code: "), validators=[DataRequired()])
    submit = SubmitField(_l("Submit"))


class TwoFALogin(FlaskForm):
    otp_code = StringField(_l("Code: "), validators=[DataRequired()])
    submit = SubmitField(_l("Submit"))
