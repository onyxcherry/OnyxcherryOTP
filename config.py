import base64
import datetime
import logging
import os
from dataclasses import dataclass
from distutils.util import strtobool

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


class Config(object):
    SECRET_KEY = (
        os.environ.get("SECRET_KEY")
        or base64.b64encode(os.urandom(32)).decode()
    )
    TWOFA_SECRET_KEY = (
        os.environ.get("TWOFA_SECRET_KEY")
        or base64.b64encode(os.urandom(32)).decode()
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or "sqlite:///" + os.path.join(basedir, "app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT") or 465)

    TESTING = strtobool(os.environ.get("TESTING") or "true")

    WTF_CSRF_ENABLED = strtobool(os.environ.get("WTF_CSRF_ENABLED") or "true")

    if TESTING:
        WTF_CSRF_ENABLED = False

    # Note that emails isn't sending when TESTING is True
    MAIL_LOCALHOST = strtobool(os.environ.get("MAIL_LOCALHOST") or "true")
    if MAIL_LOCALHOST or TESTING:
        MAIL_SERVER = "localhost"
        MAIL_PORT = "8465"
        os.environ["MAIL_SERVER"] = "localhost"
        os.environ["MAIL_PORT"] = "8465"

    ADMINS = ["postmaster@onyxcherry.pl"]

    LANGUAGES = ["en", "pl"]

    HTTPS_ENABLED = strtobool(os.environ.get("HTTPS_ENABLED") or "false")

    SESSION_COOKIE_SECURE = HTTPS_ENABLED
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"

    REMEMBER_COOKIE_DURATION = datetime.timedelta(days=1)
    REMEMBER_COOKIE_SECURE = HTTPS_ENABLED
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Strict"  # might be not implented yet

    # These recaptcha keys are test keys
    # [https://developers.google.com/recaptcha/docs/faq
    # #id-like-to-run-automated-tests-with-recaptcha.-what-should-i-do]

    RECAPTCHA_PUBLIC_KEY = ""
    RECAPTCHA_PUBLIC_KEY = (
        os.environ.get("RECAPTCHA_PUBLIC_KEY")
        or "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI"
    )
    RECAPTCHA_PRIVATE_KEY = (
        os.environ.get("RECAPTCHA_PRIVATE_KEY")
        or "6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe"
    )

    RP_ID = os.environ.get("RP_ID") or "localhost"

    PREFERRED_URL_SCHEME = "https"

    ATTESTATION = os.environ.get("ATTESTATION") or "direct"

    BCRYPT_LOG_ROUNDS = 13

    # Very useful when debugging especially templates. Change to True if needed
    EXPLAIN_TEMPLATE_LOADING = False


@dataclass
class CSPSettings:
    csp = {
        "default-src": "'self'",
        "script-src": ["'strict-dynamic'"],
        "style-src": ["'self'"],
        "img-src": ["'self'", "data:"],
        "frame-src": ["https://www.google.com/recaptcha/"],
        "object-src": "'none'",
        "base-uri": "'none'",
        "report-uri": "https://onyxcherryotp.report-uri.com/r/d/csp/enforce",
    }
    content_security_policy = csp
    content_security_policy_nonce_in = ["script-src", "style-src"]
    force_https = Config.HTTPS_ENABLED
    frame_options = "DENY"
    session_cookie_secure = Config.HTTPS_ENABLED
    session_cookie_http_only = True
    strict_transport_security = True
    referrer_policy = "strict-origin-when-cross-origin"

    # Consider adding 'unsafe-inline'
    # (ignored by browsers supporting nonces/hashes)
    # to be backward compatible with older browsers.

    # Consider adding https: and http: url schemes
    # (ignored by browsers supporting 'strict-dynamic')
    # to be backward compatible with older browsers.
    # [https://csp-evaluator.withgoogle.com/]


def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger
