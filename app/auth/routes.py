import os
from base64 import b64encode
from datetime import datetime, timedelta

import jwt
import pyotp
from flask import (abort, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)
from flask_babel import _
from flask_login import (confirm_login, current_user, fresh_login_required,
                         login_fresh, login_required, login_user, logout_user)
from werkzeug.urls import url_parse

from app import db
from app.auth import bp
from app.auth.email import send_password_reset_email
from app.auth.forms import (CheckOTPCode, LoginForm, RefreshLogin,
                            RegistrationForm, ResetPasswordForm,
                            ResetPasswordRequestForm, TwoFALogin)
from app.models import OTP, ResetPasswordValue, User


@bp.route('/')
def root():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    return redirect(url_for('auth.login'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash(_('Invalid username or password'))
            return redirect(url_for('auth.login'))
        onetimepass = OTP.query.filter_by(user_id=user.id).first()
        remember_me = form.remember_me.data
        if onetimepass and onetimepass.is_valid == 1:
            form = TwoFALogin()
            token = user.set_valid_credentials(remember_me)
            return render_template('auth/2fa_login.html', form=form, token=token)
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/login.html', title=_('Sign In'), form=form)

@bp.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash(_('Congratulations, you are now a registered user!'))
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', title=_('Register'), form=form)

@bp.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:          
            reset_password_db = ResetPasswordValue.query.filter_by(user_id=user.id).first()
            if reset_password_db: user.delete_expired_tokens(reset_password_db)        
            value = b64encode(os.urandom(16)).decode('utf-8')
            token = user.get_reset_password_token(value)
            db_date = datetime.utcnow()
            if not reset_password_db:
                reset_password_new = ResetPasswordValue(first_value=value, first_date=db_date, user_id=user.id)
            elif not reset_password_db.first_value:         
                reset_password_db.first_value = value
                reset_password_db.first_date = db_date
            elif not reset_password_db.second_value:
                reset_password_db.second_value = value
                reset_password_db.second_date = db_date
            db.session.add(reset_password_db)
            db.session.commit()
            send_password_reset_email(user, token)
        flash(_('Check your email for the instructions to reset your password.'))
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password_request.html', title=_('Reset Password'), form=form)

@bp.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    user, value = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('main.index'))
    reset_password_db = ResetPasswordValue.query.filter_by(user_id=user.id).first()
    if reset_password_db:       
        user.delete_expired_tokens(reset_password_db)   
    form = ResetPasswordForm()
    if form.validate_on_submit():
        if value == reset_password_db.first_value:
            reset_password_db.first_value = None
            reset_password_db.first_date = None
            user.set_password(form.password.data)
        elif value == reset_password_db.second_value:
            reset_password_db.second_value = None
            reset_password_db.second_date = None
            user.set_password(form.password.data)
        else:
            flash(_('Invalid or expired token'))
            return redirect(url_for('auth.reset_password_request'))
        db.session.add(reset_password_db)
        db.session.add(user)
        db.session.commit()
        flash(_('Your password has been reset.'))
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)

@bp.route('/activate_2fa')
@login_required
@fresh_login_required
def twofa():
    form = CheckOTPCode()
    return render_template('auth/turn_on_2fa.html', title=_('2FA'), form=form)
    
@bp.route('/refresh', methods=['GET', 'POST'])
@login_required
def refresh_login():
    if current_user.is_authenticated and login_fresh():
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    form = RefreshLogin()
    user = User.query.filter_by(id=current_user.get_id()).first()
    if form.validate_on_submit():
        if user.check_password(form.password.data):
            confirm_login()
        else:
            flash(_('Invalid password'))
            return redirect(url_for('auth.refresh_login'))
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    return render_template('auth/refresh_login.html', title=_('Refresh your session'), form=form)

@bp.route('/generate_token')
def generate_token():
    if current_user.is_anonymous:
        abort(401)
    user_otp = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if not user_otp:
        onetimepass = OTP(secret=pyotp.random_base32(), is_valid=False, user_id=current_user.get_id())
        db.session.add(onetimepass)
        db.session.commit()
    elif user_otp.is_valid == False:
        user_otp.secret = pyotp.random_base32()
        db.session.add(user_otp)
        db.session.commit()
    otp_secret = OTP.query.filter_by(user_id=current_user.get_id()).first().secret
    user = User.query.filter_by(id=current_user.get_id()).first()
    app_qrcode = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=user.email, issuer_name='Onyxcherry OTP')
    status = 'OK'
    resp = {
        "status": status,
        "secret": otp_secret,
        "app_qrcode": app_qrcode
    }
    return jsonify(resp)

@bp.route('/checkcode', methods=['POST'])
def checkcode():
    if current_user.is_anonymous:
        abort(401)
    otp_data = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if otp_data.is_valid == 1:
        return '2FA is enabled.'
    latest = pyotp.TOTP(otp_data.secret).verify(request.data.decode())
    previous = pyotp.TOTP(otp_data.secret).at(datetime.now()-timedelta(seconds=30)) == request.data.decode()
    if (latest or previous) and otp_data.is_valid == 0: #False
        otp_data.is_valid = 1
        db.session.add(otp_data)
        db.session.commit()
        return 'OK'
    return 'NOT'
        
@bp.route('/check_2fa_login', methods=['POST'])
def check_2fa_login():
    token = request.form.get('2fa_token')
    otp_code = request.form.get('otp_code')
    try:
        jwt_decoded = jwt.decode(token, current_app.config['TWOFA_SECRET_KEY'],
            algorithms=['HS256'])
        jwt_username = jwt_decoded['twofa_login']
        jwt_exp = jwt_decoded['exp']
        jwt_remember_me = jwt_decoded['remember_me']
    except:
            flash(_('Invalid token!'))
            return redirect(url_for('auth.login'))
    user = User.query.filter_by(username=jwt_username).first()
    user_id = user.id
    otp_secret_database = OTP.query.filter_by(user_id=user_id).first().secret
    latest = pyotp.TOTP(otp_secret_database).verify(otp_code)
    previous = pyotp.TOTP(otp_secret_database).at(datetime.now()-timedelta(seconds=30)) == otp_code
    if latest or previous:
        login_user(user, remember=jwt_remember_me)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('main.index')
        return redirect(next_page)
    flash(_('Invalid OTP code'))
    return redirect(url_for('auth.login'))

@bp.route('/2fa_deactivate')
@login_required
@fresh_login_required
def deactivate_2fa():
    otp_data = OTP.query.filter_by(user_id=current_user.get_id()).first()
    if otp_data.is_valid == 1:
        otp_data.is_valid = 0
        db.session.add(otp_data)
        db.session.commit()
        return render_template('auth/deactivated_2fa.html')
    return redirect(url_for('main.index'))
