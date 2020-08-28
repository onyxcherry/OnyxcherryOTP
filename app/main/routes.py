from app.main import bp
from app.models import OTP
from flask import flash, redirect, render_template, url_for
from flask_babel import _
from flask_login import current_user, login_required


@bp.route("/")
@bp.route("/index")
@login_required
def index():
    return render_template("index.html", title=_("Home"))


@bp.route("/settings")
@login_required
def settings():
    user_twofa = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if user_twofa and user_twofa.is_valid == 1:
        return render_template(
            "settings/settings.html", title=_("Settings"), twofa_enabled=True
        )
    return render_template("settings/settings.html", title=_("Settings"))
