import os
from dataclasses import dataclass

import fakeredis
import redis
from config import Config, CSPSettings
from dotenv import load_dotenv
from flask import Flask, current_app, render_template, request
from flask_babel import Babel
from flask_babel import lazy_gettext as _l
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect

pool = redis.ConnectionPool(
    host=Config.REDIS_HOST, port=Config.REDIS_PORT, db=0
)
rds = redis.Redis(connection_pool=pool)

try:
    rds.ping()
except redis.exceptions.ConnectionError:
    rds = fakeredis.FakeStrictRedis()

db = SQLAlchemy()
migrate = Migrate()
login = LoginManager()
login.login_view = "auth.login"
login.login_message = _l("Please log in to access this page.")
login.refresh_view = "auth.refresh_login"
login.needs_refresh_message = _l(
    u"To protect your account, please reauthenticate to access this page."
)
login.needs_refresh_message_category = "info"
# login.session_protection = "strong"
# Above strong mode causes deleting session cookie after recovered
# cookie by remember-me option

flask_bcrypt = Bcrypt()
babel = Babel()
csrf = CSRFProtect()
talisman = Talisman()


def page_not_found(e):
    return render_template("errors/404.html"), 404


def internal_error(e):
    db.session.rollback()
    return render_template("errors/500.html"), 500


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login.init_app(app)
    csrf.init_app(app)
    babel.init_app(app)
    flask_bcrypt.init_app(app)

    csp = CSPSettings()
    talisman.init_app(
        app,
        content_security_policy=csp.content_security_policy,
        content_security_policy_nonce_in=csp.content_security_policy_nonce_in,
        force_https=csp.force_https,
        frame_options=csp.frame_options,
        session_cookie_secure=csp.session_cookie_secure,
        session_cookie_http_only=csp.session_cookie_http_only,
        strict_transport_security=csp.strict_transport_security,
        referrer_policy=csp.referrer_policy,
    )

    with app.app_context():
        if db.engine.url.drivername == "sqlite":
            migrate.init_app(app, db, render_as_batch=True)
        else:
            migrate.init_app(app, db)

    from app.errors import bp as errors_bp

    app.register_blueprint(errors_bp)

    app.register_error_handler(404, page_not_found)
    app.register_error_handler(500, internal_error)

    from app.auth import bp as auth_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")

    from app.twofa import bp as twofa_bp

    app.register_blueprint(twofa_bp, url_prefix="/twofa")

    from app.webauthn import bp as webauthn_bp

    app.register_blueprint(webauthn_bp, url_prefix="/webauthn")

    csrf.exempt(webauthn_bp)

    from app.main import bp as main_bp

    app.register_blueprint(main_bp)

    return app


@babel.localeselector
def get_locale():
    return request.accept_languages.best_match(current_app.config["LANGUAGES"])


from app import models
