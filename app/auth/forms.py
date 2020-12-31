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


class LoginForm(FlaskForm):
    username = StringField(_l("Username"), validators=[DataRequired()])
    password = PasswordField(_l("Password"), validators=[DataRequired()])
    remember_me = BooleanField(_l("Remember me"))
    submit = SubmitField(_l("Sign in"))


class RegistrationForm(FlaskForm):
    username = StringField(
        _l("Username"), validators=[DataRequired(), Length(min=3, max=64)]
    )
    email = StringField(
        _l("Email"), validators=[DataRequired(), Email(), Length(max=120)]
    )
    password = PasswordField(
        _l("Password"), validators=[DataRequired(), Length(min=8, max=128)]
    )
    password2 = PasswordField(
        _l("Repeat Password"),
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    # recaptcha = RecaptchaField()
    # RecaptchaField currently doesn't support csp_nonce()
    submit = SubmitField(_l("Register"))

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user or not username.data.isascii():
            raise ValidationError(_("Please use a different username."))

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(_("Please use a different email address."))


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(_l("Email"), validators=[DataRequired(), Email()])
    submit = SubmitField(_l("Request password reset"))


class ResetPasswordForm(FlaskForm):
    password = PasswordField(
        _l("Password"), validators=[DataRequired(), Length(min=8, max=128)]
    )
    password2 = PasswordField(
        _l("Repeat password"),
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    submit = SubmitField(_l("Reset my password"))


class RefreshLogin(FlaskForm):
    password = PasswordField(_l("Password"), validators=[DataRequired()])
    submit = SubmitField(_l("Submit"))
