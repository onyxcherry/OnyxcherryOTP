from app.main import bp
from app.models import OTP, User
from flask import current_app, render_template, request
from flask_babel import _
from flask_login import current_user, login_required


@bp.route("/")
@bp.route("/index")
def index():
    return render_template("index.html", title=_("Home"), default_content=True)


@bp.route("/settings")
@login_required
def settings():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    user_twofa = OTP.query.filter_by(user_id=database_id).first()
    if user_twofa and user_twofa.is_valid is True:
        return render_template(
            "settings/settings.html",
            title=_("Settings"),
            twofa_enabled=True,
            settings_active=True,
        )
    return render_template(
        "settings/settings.html", title=_("Settings"), settings_active=True
    )
