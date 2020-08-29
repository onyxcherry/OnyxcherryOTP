import pyotp
import pytest
from app import Config, create_app, db
from app.models import User


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    BCRYPT_LOG_ROUNDS = 4
    WTF_CSRF_ENABLED = False
    SECRET_KEY = "s2yvxuwZ7Ipf5JKv6uV7y85AfJJdhhSPq65bKZtH7l4="
    TWOFA_SECRET_KEY = "cryG2D0C95mlO9r/rnple7FOdQhYsPL8boXB/qOXuPM="


@pytest.fixture(scope="session")
def user():
    user = User(username="paul", email="paul@example.com")
    return user


@pytest.fixture(scope="module")
def test_client():
    onyxcherry_otp = create_app(TestConfig)

    testing_client = onyxcherry_otp.test_client()

    app_context = onyxcherry_otp.app_context()
    app_context.push()

    yield testing_client

    app_context.pop()


@pytest.fixture(scope="module")
def init_database():

    db.create_all()

    user1 = User(username="straw_berry", email="strawberry8@example.com")
    user1.set_password("EJew@MHHQ7x-g.4<")
    user2 = User(username="josh_9", email="josh+otpapp@gmail.com")
    user2.set_password("m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=")
    user3 = User(username="dave", email="dave16@outlook.com")
    user3.set_password("wselfknskjdksdaiujlj")
    db.session.add(user1)
    db.session.add(user2)
    db.session.add(user3)

    db.session.commit()

    yield db

    db.drop_all()
