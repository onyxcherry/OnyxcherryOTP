import os
from base64 import b64encode
from datetime import datetime, timedelta

import jwt
import pyotp
from app import db
from app.auth import bp
from app.auth.email import send_password_reset_email
from app.auth.forms import (
    CheckOTPCode,
    LoginForm,
    RefreshLogin,
    RegistrationForm,
    ResetPasswordForm,
    ResetPasswordRequestForm,
    TwoFALogin,
)
from app.models import OTP, ResetPassword, User
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


@bp.route("/")
def root():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash(_("Invalid username or password"))
            return redirect(url_for("auth.login"))
        user_otp = OTP.query.filter_by(user_id=user.id).first()
        remember_me = form.remember_me.data
        if user_otp and user_otp.is_valid == 1:
            user_otp.remaining_attempts = 3
            db.session.add(user_otp)

            form = TwoFALogin()
            token = user.set_valid_credentials(remember_me)
            response = make_response(
                render_template("auth/2fa_login.html", form=form)
            )
            response.set_cookie(
                "token",
                value=token,
                max_age=60,
                secure=False,
                httponly=True,
                samesite="Strict",
            )
            db.session.commit()
            return response
        login_user(user, remember=form.remember_me.data)
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    return render_template("auth/login.html", title=_("Sign In"), form=form)


@bp.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        new_user = User(username=form.username.data, email=form.email.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash(_("Congratulations, you are now a registered user!"))
        return redirect(url_for("auth.login"))
    return render_template(
        "auth/register.html", title=_("Register"), form=form
    )


@bp.route("/reset_password_request", methods=["GET", "POST"])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash(
                _(
                    "Check your email for the instructions "
                    "to reset your password."
                )
            )
            return redirect(url_for("auth.login"))

        confirming_value = user.get_random_base64_value()
        token = user.get_reset_password_token(confirming_value)
        now = datetime.utcnow()
        should_send_mail = False

        reset_password = ResetPassword.query.filter_by(user_id=user.id).first()
        if reset_password:
            user.delete_expired_tokens(reset_password)
            if not reset_password.first_value:
                reset_password.first_value = confirming_value
                reset_password.first_date = now
                should_send_mail = True
            elif not reset_password.second_value:
                reset_password.second_value = confirming_value
                reset_password.second_date = now
                should_send_mail = True
            db.session.add(reset_password)
        else:
            reset_password_new = ResetPassword(
                first_value=confirming_value, first_date=now, user_id=user.id
            )
            db.session.add(reset_password_new)
            should_send_mail = True
        db.session.commit()
        if should_send_mail:
            send_password_reset_email(user, token)

        flash(
            _("Check your email for the instructions to reset your password.")
        )
        return redirect(url_for("auth.login"))
    return render_template(
        "auth/reset_password_request.html",
        title=_("Reset Password"),
        form=form,
    )


@bp.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    username, value = User.verify_reset_password_token(token)
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for("main.index"))
    reset_password = ResetPassword.query.filter_by(user_id=user.id).first()
    if reset_password:
        user.delete_expired_tokens(reset_password)
    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        if value == reset_password.first_value:
            reset_password.first_value = None
            reset_password.first_date = None
            user.set_password(password)
        elif value == reset_password.second_value:
            reset_password.second_value = None
            reset_password.second_date = None
            user.set_password(password)
        else:
            flash(_("Invalid or expired token"))
            return redirect(url_for("auth.reset_password_request"))
        db.session.add(reset_password)
        db.session.add(user)
        db.session.commit()
        flash(_("Your password has been reset."))
        return redirect(url_for("auth.login"))
    return render_template("auth/reset_password.html", form=form)


@bp.route("/activate_2fa")
@login_required
@fresh_login_required
def twofa():
    form = CheckOTPCode()
    return render_template("auth/turn_on_2fa.html", title=_("2FA"), form=form)


@bp.route("/refresh", methods=["GET", "POST"])
@login_required
def refresh_login():
    if current_user.is_authenticated and login_fresh():
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    form = RefreshLogin()
    user = User.query.filter_by(id=current_user.get_id()).first()
    if form.validate_on_submit():
        if user.check_password(form.password.data):
            confirm_login()
        else:
            flash(_("Invalid password"))
            return redirect(url_for("auth.refresh_login"))
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    return render_template(
        "auth/refresh_login.html", title=_("Refresh your session"), form=form
    )


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


@bp.route("/check_2fa_login", methods=["POST"])
def check_2fa_login():
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
        jwt_exp = jwt_decoded["exp"]
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


@bp.route("/2fa_deactivate")
@login_required
@fresh_login_required
def deactivate_2fa():
    otp_data = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if otp_data.is_valid == 1:
        otp_data.is_valid = 0
        db.session.add(otp_data)
        db.session.commit()
        return render_template("auth/deactivated_2fa.html")
    return redirect(url_for("main.index"))
