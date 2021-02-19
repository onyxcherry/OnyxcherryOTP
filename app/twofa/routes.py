from datetime import datetime, timedelta

import pyotp
from app import db
from app.models import OTP, User
from app.twofa import bp
from app.twofa.forms import CheckOTPCode
from flask import (
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_babel import _, gettext  # noqa: F401
from flask_babel import lazy_gettext as _l  # noqa: F401
from flask_login import (
    current_user,
    fresh_login_required,
    login_required,
    login_user,
)
from werkzeug.urls import url_parse


def get_next_page(next_from_request: str) -> str:
    next_page = next_from_request
    if not next_page or url_parse(next_page).netloc != "":
        next_page = url_for("main.index")
    return next_page


def generate_base32_secret():
    return pyotp.random_base32()


@bp.route("/activate")
@login_required
@fresh_login_required
def activate():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    otp = OTP.query.filter_by(user_id=database_id).first()
    if otp and otp.is_valid is True:
        return redirect(url_for("main.settings"))
    form = CheckOTPCode()
    return render_template("twofa/turn_on.html", title=_("2FA"), form=form)


@bp.route("/generate_token")
@fresh_login_required
def generate_token():
    if current_user.is_anonymous:
        abort(401)
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    otp = OTP.query.filter_by(user_id=database_id).first()
    if not otp:
        new_otp = OTP(
            secret=generate_base32_secret(),
            is_valid=False,
            user_id=database_id,
        )
        db.session.add(new_otp)
        db.session.commit()
    elif otp.is_valid is False:
        otp.secret = generate_base32_secret()
        db.session.add(otp)
        db.session.commit()
    current_otp_secret = (
        OTP.query.filter_by(user_id=database_id).first().secret
    )
    user = User.query.filter_by(did=database_id).first()
    app_qrcode_source = pyotp.totp.TOTP(current_otp_secret).provisioning_uri(
        name=user.email, issuer_name="Onyxcherry OTP"
    )

    response = {
        "status": "OK",
        "secret": current_otp_secret,
        "app_qrcode": app_qrcode_source,
    }
    return jsonify(response)


@bp.route("/checkcode", methods=["POST"])
@fresh_login_required
def checkcode():
    if current_user.is_anonymous:
        abort(401)
    # Default message in case of any problem
    status = "NOT"
    message = _l("An error occured. Please contact the administrator.")
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    user_otp = OTP.query.filter_by(user_id=database_id).first()
    if user_otp and user_otp.is_valid is True:
        message = "2FA is enabled."
    latest = pyotp.TOTP(user_otp.secret).verify(request.form.get("otp_code"))
    previous = pyotp.TOTP(user_otp.secret).at(
        datetime.now() - timedelta(seconds=30)
    ) == request.form.get("otp_code")
    if latest or previous:
        user_otp.is_valid = 1
        db.session.add(user_otp)
        db.session.commit()
        status = "OK"
        message = _l("Turned on 2FA. You could go to the main page.")
    else:
        status = "NOT"
        message = _l("Invalid OTP code! Try again.")
    response = {"status": status, "message": message}
    return jsonify(response)


def check_last_otp_code(secret: str, code: str) -> bool:
    return pyotp.TOTP(secret).verify(code)


def check_prior_latest_otp_code(secret: str, code: str) -> bool:
    return (
        pyotp.TOTP(secret).at(datetime.now() - timedelta(seconds=30)) == code
    )


@bp.route("/check_login", methods=["POST"])
def check_login():
    otp_code = request.form.get("otp_code")
    token = request.cookies.get("token")
    if not token:
        abort(401)
    username, remember_me = User.verify_twofa_login_token(token.encode())
    if not username:
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    otp = OTP.query.filter_by(user_id=user.did).first()
    if otp.remaining_attempts < 1:
        abort(401)
    latest = check_last_otp_code(otp.secret, otp_code)
    prior_latest = check_prior_latest_otp_code(otp.secret, otp_code)
    if latest or prior_latest:
        login_user(user, remember=remember_me)
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    # regardless of the correctness of the token, the remaining number
    # of attempts should decrease
    otp.remaining_attempts -= 1
    db.session.add(otp)
    db.session.commit()
    flash(_("Invalid OTP code"))
    return redirect(url_for("auth.login"))


@bp.route("/deactivate")
@login_required
@fresh_login_required
def deactivate():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    otp_data = OTP.query.filter_by(user_id=database_id).first()
    if otp_data.is_valid == 1:
        otp_data.is_valid = 0
        db.session.add(otp_data)
        db.session.commit()
        return render_template("twofa/deactivated.html", settings_active=True)
    return redirect(url_for("main.index"))
