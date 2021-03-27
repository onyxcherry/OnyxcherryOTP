from distutils.util import strtobool

import bcrypt
import pyotp
from app import csrf, current_app, db, rds
from app.auth import bp
from app.auth.email import send_password_reset_email
from app.auth.forms import (
    LoginForm,
    RefreshLogin,
    RegistrationForm,
    ResetPasswordForm,
    ResetPasswordRequestForm,
)
from app.models import OTP, User, Webauthn
from app.twofa.forms import CheckOTPCode
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

cookie_flags = {
    "key": "token",
    "max_age": 90,
    "httponly": True,
    "samesite": "Strict",
}


def get_next_page(next_from_request: str) -> str:
    next_page = next_from_request
    if not next_page or url_parse(next_page).netloc != "":
        next_page = url_for("main.index")
    return next_page


def generate_base32_secret():
    return pyotp.random_base32()


def get_passwd_reset_key_prefix(user_database_id: int):
    return f"rpr:{user_database_id}"


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
        sample_salt = bcrypt.gensalt(
            rounds=current_app.config.get("BCRYPT_LOG_ROUNDS")
        )
        sample_password = bcrypt.hashpw(b"aaaa", sample_salt)
        if user is None:
            user = User(password_hash=sample_password)
        if not user.check_password(form.password.data):
            flash(_("Invalid username or password"))
            return redirect(url_for("auth.login"))
        user_otp = OTP.query.filter_by(user_id=user.did).first()
        remember_me = form.remember_me.data
        secure_flag = (current_app.config.get("HTTPS_ENABLED"),)

        webauthn = Webauthn.query.filter_by(user_id=user.did).first()
        if webauthn and webauthn.is_enabled is True:
            token = user.set_valid_credentials(remember_me)
            response = make_response(
                render_template("webauthn/login_with_webauthn.html")
            )
            response.set_cookie(
                value=token, secure=secure_flag, **cookie_flags,
            )
            return response

        elif user_otp and user_otp.is_valid == 1:
            user_otp.remaining_attempts = 3
            db.session.add(user_otp)

            form = CheckOTPCode()
            token = user.set_valid_credentials(remember_me)
            response = make_response(
                render_template("twofa/login_with_twofa.html", form=form)
            )
            response.set_cookie(
                value=token, secure=secure_flag, **cookie_flags,
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
        "auth/register.html",
        title=_("Register"),
        form=form,
        recaptcha_public_key=current_app.config.get("RECAPTCHA_PUBLIC_KEY"),
    )


@bp.route("/reset_password_request", methods=["GET", "POST"])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        should_send_mail = True
        if user is None:
            # prevent timing enumeration attacks
            user = User(username="someuser")
            should_send_mail = False

        secret_value = user.get_random_base64_value()
        jwt_token = user.get_reset_password_token(secret_value)
        reset_pwd_keys = rds.keys(f"{get_passwd_reset_key_prefix(user.did)}:*")
        if len(reset_pwd_keys) < current_app.config.get(
            "MAX_RESET_PASSWORD_TOKENS"
        ):
            rds.set(
                f"{get_passwd_reset_key_prefix(user.did)}:{secret_value}",
                "2",  # whatever value
                ex=current_app.config.get("RESET_PASSWORD_TOKEN_EXPIRE_TIME"),
            )
            if should_send_mail:
                send_password_reset_email(user, jwt_token)
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
    if user is None:
        return redirect(url_for("main.index"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.password.data
        # check if secret value is valid -> atomically delete it
        if rds.delete(f"{get_passwd_reset_key_prefix(user.did)}:{value}"):
            user.set_password(new_password)
            db.session.add(user)
            db.session.commit()
            flash(_("Your password has been reset."))
            return redirect(url_for("auth.login"))
        flash(_("Invalid or expired token"))
        return redirect(url_for("auth.reset_password_request"))
    return render_template("auth/reset_password.html", form=form)


@bp.route("/refresh", methods=["GET", "POST"])
@login_required
def refresh_login():
    if current_user.is_authenticated and login_fresh():
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    prefered_webauthn = strtobool(request.args.get("webauthn", "false"))
    if prefered_webauthn:
        return render_template("webauthn/login_with_webauthn.html")
    form = RefreshLogin()
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    user = User.query.filter_by(did=database_id).first()
    webauthn = Webauthn.query.filter_by(user_id=database_id).first()
    webauthn_enabled = webauthn.is_enabled if webauthn is not None else False
    if form.validate_on_submit():
        if user.check_password(form.password.data):
            confirm_login()
        else:
            flash(_("Invalid password"))
            return redirect(url_for("auth.refresh_login"))
        next_page = get_next_page(request.args.get("next"))
        return redirect(next_page)
    return render_template(
        "auth/refresh_login.html",
        title=_("Refresh your session"),
        form=form,
        webauthn_enabled=webauthn_enabled,
    )


@bp.route("/revoke")
@login_required
def revoke_other_sessions():
    got_id = current_user.get_id()
    user_database_id = User.get_database_id(got_id)
    user = User.query.filter_by(did=user_database_id).first()
    user.revoke_other_sessions()
    db.session.add(user)
    db.session.commit()
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
