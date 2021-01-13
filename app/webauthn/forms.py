from flask_babel import lazy_gettext as _l
from flask_wtf import FlaskForm
from wtforms import HiddenField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class NameKey(FlaskForm):
    credential_id = HiddenField()
    key_name = StringField(
        _l("Name: "), validators=[DataRequired(), Length(max=64)]
    )
    submit = SubmitField(_l("Submit"))
