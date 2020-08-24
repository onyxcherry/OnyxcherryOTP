import datetime
import os

from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, ".env"))


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
        WTF_CSRF_ENABLED = False

    ADMINS = ["postmaster@onyxcherry.pl"]

    LANGUAGES = ["en", "pl"]

    SESSION_COOKIE_SECURE = False  # change to True in production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"

    REMEMBER_COOKIE_DURATION = datetime.timedelta(days=1)
    REMEMBER_COOKIE_SECURE = False  # change to True in production
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Strict"  # might not implented yet

    RECAPTCHA_PUBLIC_KEY = os.environ.get("RECAPTCHA_PUBLIC_KEY")
    RECAPTCHA_PRIVATE_KEY = os.environ.get("RECAPTCHA_PRIVATE_KEY")

    PREFERRED_URL_SCHEME = "https"

    # Very useful when debugging especially templates. Change to True if needed
    EXPLAIN_TEMPLATE_LOADING = False
