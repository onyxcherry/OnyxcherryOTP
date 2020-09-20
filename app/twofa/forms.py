from flask_babel import lazy_gettext as _l
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class CheckOTPCode(FlaskForm):
    otp_code = StringField(
        _l("Code: "), validators=[DataRequired(), Length(max=6)]
    )
    submit = SubmitField(_l("Submit"))
