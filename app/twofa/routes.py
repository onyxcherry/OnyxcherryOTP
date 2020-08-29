from datetime import datetime, timedelta

import jwt
import pyotp
from app import db
from app.auth.email import send_password_reset_email
from app.auth.forms import (
    LoginForm,
    RefreshLogin,
    RegistrationForm,
    ResetPasswordForm,
    ResetPasswordRequestForm,
)
from app.models import OTP, ResetPassword, User
from app.twofa import bp
from app.twofa.forms import CheckOTPCode, TwoFALogin
from flask import (
    abort,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_babel import _
from flask_login import (
    confirm_login,
    current_user,
    fresh_login_required,
    login_fresh,
    login_required,
    login_user,
    logout_user,
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
    form = CheckOTPCode()
    return render_template("twofa/turn_on.html", title=_("2FA"), form=form)


@bp.route("/generate_token")
@fresh_login_required
def generate_token():
    if current_user.is_anonymous:
        abort(401)
    otp = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if not otp:
        new_otp = OTP(
            secret=generate_base32_secret(),
            is_valid=False,
            user_id=current_user.get_id(),
        )
        db.session.add(new_otp)
        db.session.commit()
    elif otp.is_valid is False:
        otp.secret = generate_base32_secret()
        db.session.add(otp)
        db.session.commit()
    current_otp_secret = (
        OTP.query.filter_by(user_id=current_user.get_id()).first().secret
    )
    user = User.query.filter_by(id=current_user.get_id()).first()
    app_qrcode_source = pyotp.totp.TOTP(current_otp_secret).provisioning_uri(
        name=user.email, issuer_name="Onyxcherry OTP"
    )

    status = "OK"
    # Verify the reason of returnning status
    response = {
        "status": status,
        "secret": current_otp_secret,
        "app_qrcode": app_qrcode_source,
    }
    return jsonify(response)


@bp.route("/checkcode", methods=["POST"])
@fresh_login_required
def checkcode():
    if current_user.is_anonymous:
        abort(401)
    otp_data = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if otp_data.is_valid == 1:
        return "2FA is enabled."
    latest = pyotp.TOTP(otp_data.secret).verify(request.data.decode())
    previous = (
        pyotp.TOTP(otp_data.secret).at(datetime.now() - timedelta(seconds=30))
        == request.data.decode()
    )
    if (latest or previous) and otp_data.is_valid == 0:  # False
        otp_data.is_valid = 1
        db.session.add(otp_data)
        db.session.commit()
        return "OK"
    return "NOT"


@bp.route("/check_login", methods=["POST"])
def check_login():
    token = request.cookies.get("token")
    if token:
        token = token.encode()
    else:
        abort(401)
    otp_code = request.form.get("otp_code")
    try:
        jwt_decoded = jwt.decode(
            token, current_app.config["TWOFA_SECRET_KEY"], algorithms=["HS256"]
        )
        jwt_username = jwt_decoded["twofa_login"]
        jwt_decoded["exp"]
        jwt_remember_me = jwt_decoded["remember_me"]
    except (
        jwt.exceptions.InvalidSignatureError,
        jwt.exceptions.ExpiredSignatureError,
    ):
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=jwt_username).first()
    user_id = user.id
    otp = OTP.query.filter_by(user_id=user_id).first()
    if otp.remaining_attempts < 1:
        abort(401)
    otp_secret_database = otp.secret
    latest = pyotp.TOTP(otp_secret_database).verify(otp_code)
    previous = (
        pyotp.TOTP(otp_secret_database).at(
            datetime.now() - timedelta(seconds=30)
        )
        == otp_code
    )
    if latest or previous:
        login_user(user, remember=jwt_remember_me)
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("main.index")
        return redirect(next_page)
    otp.remaining_attempts -= 1
    db.session.add(otp)
    db.session.commit()
    flash(_("Invalid OTP code"))
    return redirect(url_for("auth.login"))


@bp.route("/deactivate")
@login_required
@fresh_login_required
def deactivate():
    otp_data = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if otp_data.is_valid == 1:
        otp_data.is_valid = 0
        db.session.add(otp_data)
        db.session.commit()
        return render_template("twofa/deactivated.html")
    return redirect(url_for("main.index"))
