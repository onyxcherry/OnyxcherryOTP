from datetime import datetime

import pyotp
from app import csrf, db
from app.auth import bp
from app.auth.email import send_password_reset_email
from app.auth.forms import (
    LoginForm,
    RefreshLogin,
    RegistrationForm,
    ResetPasswordForm,
    ResetPasswordRequestForm,
)
from app.models import (
    OTP,
    ResetPassword,
    User,
    Webauthn,
    change_session_id,
    generate_sid,
)
from app.twofa.forms import CheckOTPCode
from config import Config
from flask import (
    abort,
    flash,
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


@bp.before_request
def check_csrf():
    csrf.protect()


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
        user_otp = OTP.query.filter_by(user_id=user.did).first()
        remember_me = form.remember_me.data

        webauthn = Webauthn.query.filter_by(user_id=user.did).first()
        if webauthn and webauthn.is_enabled is True:
            token = user.set_valid_credentials(remember_me)
            response = make_response(
                render_template("webauthn/login_with_webauthn.html")
            )
            response.set_cookie(
                "token",
                value=token,
                max_age=90,
                secure=Config.HTTPS_ENABLED,
                httponly=True,
                samesite="Strict",
            )
            return response
        if user_otp and user_otp.is_valid == 1:
            user_otp.remaining_attempts = 3
            db.session.add(user_otp)

            form = CheckOTPCode()
            token = user.set_valid_credentials(remember_me)
            response = make_response(
                render_template("twofa/login_with_twofa.html", form=form)
            )
            response.set_cookie(
                "token",
                value=token,
                max_age=90,
                secure=Config.HTTPS_ENABLED,
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
        new_user = User(
            username=form.username.data,
            sid=generate_sid(),
            email=form.email.data,
        )
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash(_("Congratulations, you are now a registered user!"))
        return redirect(url_for("auth.login"))
    return render_template(
        "auth/register.html",
        title=_("Register"),
        form=form,
        recaptcha_public_key=Config.RECAPTCHA_PUBLIC_KEY,
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

        reset_password = ResetPassword.query.filter_by(
            user_id=user.did
        ).first()
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
                first_value=confirming_value, first_date=now, user_id=user.did
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
    reset_password = ResetPassword.query.filter_by(user_id=user.did).first()
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


@bp.route("/refresh", methods=["GET", "POST"])
@login_required
def refresh_login():
    if current_user.is_authenticated and login_fresh():
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    form = RefreshLogin()
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    user = User.query.filter_by(did=database_id).first()
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


@bp.route("/revoke")
@login_required
def revoke_other_sessions():
    got_id = current_user.get_id()
    user_database_id = User.get_database_id(got_id)
    user = User.query.filter_by(did=user_database_id).first()
    change_session_id(user)
    login_user(user)
    flash(_("Revoked other sessions."))
    return redirect(url_for("main.index"))


@bp.route("/available_options")
def available_options():
    token = request.cookies.get("token")
    if not token:
        abort(401)
    username, remember_me = User.verify_twofa_login_token(token.encode())
    if not username:
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    database_id = user.did

    webauthn_available = False
    otp_available = False

    webauthn = Webauthn.query.filter_by(user_id=database_id).first()
    if webauthn and webauthn.is_enabled:
        webauthn_available = True

    otp = OTP.query.filter_by(user_id=database_id).first()
    if otp and otp.is_valid:
        otp_available = True

    # Add backup codes in future

    return render_template(
        "auth/available_options.html",
        webauthn_available=webauthn_available,
        otp_available=otp_available,
        backup_code_available=False,
    )


@bp.route("/use_otp")
def use_otp():
    token = request.cookies.get("token")
    if not token:
        abort(401)
    username, remember_me = User.verify_twofa_login_token(token.encode())
    if not username:
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    user_otp = OTP.query.filter_by(user_id=user.did).first()
    if user_otp and user_otp.is_valid == 1:
        form = CheckOTPCode()
        return render_template("twofa/login_with_twofa.html", form=form)
    return redirect(url_for("auth.login"))


@bp.route("/use_webauthn")
def use_webauthn():
    token = request.cookies.get("token")
    if not token:
        abort(401)
    username, remember_me = User.verify_twofa_login_token(token.encode())
    if not username:
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    webauthn = Webauthn.query.filter_by(user_id=user.did).first()
    if webauthn and webauthn.is_enabled is True:
        return render_template("webauthn/login_with_webauthn.html")
    return redirect(url_for("auth.login"))
