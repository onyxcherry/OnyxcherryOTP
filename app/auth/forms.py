from app.models import User
from flask_babel import _
from flask_babel import lazy_gettext as _l
from flask_wtf import FlaskForm, RecaptchaField
from sqlalchemy import func
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
        _l("Email"), validators=[DataRequired(), Email(), Length(max=256)]
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
    recaptcha = RecaptchaField()
    # RecaptchaField currently doesn't support csp_nonce()
    # See unmerged [PR](https://github.com/lepture/flask-wtf/pull/312)
    # However, despite this we could render the field by hand
    # and check corectness by RecaptchaField
    submit = SubmitField(_l("Register"))

    # custom validation function - they are handled by WTF's Form class method
    # validate(self, extra_validators=None)
    # [https://github.com/wtforms/wtforms/blob/244c8d6b15accb3e2efd622241e5f7c1cc8abb9d/wtforms/form.py#L299] # noqa: E501, B950
    def validate_username(self, username_field):
        user = User.query.filter(
            func.lower(User.username) == username_field.data.lower()
        ).first()
        if user or not username_field.data.isascii():
            raise ValidationError(_("Please use a different username."))

    def validate_email(self, email_field):
        # make validation case-insensitive for the sake of security
        user = User.query.filter(
            func.lower(User.email) == email_field.data.lower()
        ).first()
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
