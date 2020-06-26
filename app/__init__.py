import logging
import os
from logging.handlers import RotatingFileHandler, SMTPHandler

from flask import Flask, current_app, request
from flask_babel import Babel
from flask_babel import lazy_gettext as _l
from flask_bcrypt import Bcrypt
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy

from config import Config

db = SQLAlchemy()

login = LoginManager()
login.login_view = 'auth.login'
login.login_message = _l('Please log in to access this page.')
login.refresh_view = 'auth.refresh_login'
login.needs_refresh_message = _l(u'To protect your account, please reauthenticate to access this page.')
login.needs_refresh_message_category = "info"
# login.session_protection = "strong"
# Above strong mode causes deleting session cookie after recovered cookie by remember-me option

mail = Mail()
bootstrap = Bootstrap()
bcrypt = Bcrypt()
babel = Babel()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login.init_app(app)
    mail.init_app(app)
    bootstrap.init_app(app)
    babel.init_app(app)

    from app.errors import bp as errors_bp
    app.register_blueprint(errors_bp)

    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')

    from app.main import bp as main_bp
    app.register_blueprint(main_bp)

    return app


@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(current_app.config['LANGUAGES'])

from app import models