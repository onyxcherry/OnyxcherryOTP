import datetime
import logging
import os
from dataclasses import dataclass

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))

HTTPS_ENABLED = False
if os.environ.get("HTTPS_ENABLED", "").lower() == "true":
    HTTPS_ENABLED = True


@dataclass
class CSPSettings:
    csp = {
        "default-src": "'self'",
        "script-src": [
            "'strict-dynamic'",
            "'unsafe-inline'",
            "http:",
            "https:",
        ],
        "style-src": [
            "'self'",
            "'unsafe-inline'",
            "https://stackpath.bootstrapcdn.com",
        ],
        "object-src": "'none'",
        "base-uri": "'none'",
        "require-trusted-types-for": "'script'",
        "report-uri": "https://onyxcherryotp.report-uri.com/r/d/csp/enforce",
    }
    content_security_policy = csp
    content_security_policy_nonce_in = ["script-src"]
    force_https = HTTPS_ENABLED
    frame_options = "DENY"
    session_cookie_secure = HTTPS_ENABLED
    session_cookie_http_only = True


class Config(object):
    SECRET_KEY = (
        os.environ.get("SECRET_KEY") or "random-string-if-not-specified-in-env"
    )
    TWOFA_SECRET_KEY = (
        os.environ.get("TWOFA_SECRET_KEY")
        or "another-random-string-if-not-specified-in-env"
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or "sqlite:///" + os.path.join(basedir, "app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT") or 465)

    TESTING = os.environ.get("TESTING") is not None

    # Note that emails isn't sending when TESTING is True
    if os.environ.get("MAIL_LOCALHOST") is not None or TESTING:
        MAIL_SERVER = "localhost"
        MAIL_PORT = "8465"
        os.environ["MAIL_SERVER"] = "localhost"
        os.environ["MAIL_PORT"] = "8465"

    ADMINS = ["postmaster@onyxcherry.pl"]

    LANGUAGES = ["en", "pl"]

    SESSION_COOKIE_SECURE = HTTPS_ENABLED
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"

    REMEMBER_COOKIE_DURATION = datetime.timedelta(days=1)
    REMEMBER_COOKIE_SECURE = HTTPS_ENABLED
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Strict"  # might be not implented yet

    RECAPTCHA_PUBLIC_KEY = os.environ.get("RECAPTCHA_PUBLIC_KEY")
    RECAPTCHA_PRIVATE_KEY = os.environ.get("RECAPTCHA_PRIVATE_KEY")

    PREFERRED_URL_SCHEME = "https"

    # Very useful when debugging especially templates. Change to True if needed
    EXPLAIN_TEMPLATE_LOADING = False


def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger
