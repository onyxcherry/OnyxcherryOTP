from flask_babel import _
from flask_babel import lazy_gettext as _l
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length

from app.models import User

class LoginForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired()])
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    remember_me = BooleanField(_l('Remember Me'))
    submit = SubmitField(_l('Sign In'))


class RegistrationForm(FlaskForm):
    username = StringField(_l('Username'), validators=[DataRequired(), Length(min=3, max=64)])
    email = StringField(_l('Email'), validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField(_l('Password'), validators=[DataRequired(), Length(min=8, max=128)])
    password2 = PasswordField(
        _l('Repeat Password'), validators=[DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField()
    submit = SubmitField(_l('Register'))

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError(_('Please use a different username.'))

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError(_('Please use a different email address.'))


class ResetPasswordRequestForm(FlaskForm):
    email = StringField(_l('Email'), validators=[DataRequired(), Email()])
    submit = SubmitField(_l('Request Password Reset'))


class ResetPasswordForm(FlaskForm):
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    password2 = PasswordField(
        _l('Repeat Password'), validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField(_l('Request Password Reset'))

class RefreshLogin(FlaskForm):
    password = PasswordField(_l('Password'), validators=[DataRequired()])
    submit = SubmitField(_l('Submit'))

class CheckOTPCode(FlaskForm):
    password = StringField(_l('Code: '), validators=[DataRequired()])
    submit = SubmitField(_l('Submit'))

class TwoFALogin(FlaskForm):
    otp_code = StringField(_l('Code: '), validators=[DataRequired()])
    submit = SubmitField(_l('Submit'))