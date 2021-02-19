import pytest
from app import Config, create_app, db
from app.models import User, Webauthn, generate_sid


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    WTF_CSRF_METHODS = []
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    BCRYPT_LOG_ROUNDS = 4
    SECRET_KEY = "s2yvxuwZ7Ipf5JKv6uV7y85AfJJdhhSPq65bKZtH7l4="
    TWOFA_SECRET_KEY = "cryG2D0C95mlO9r/rnple7FOdQhYsPL8boXB/qOXuPM="


@pytest.fixture(scope="session")
def user():
    user = User(username="paul", sid=generate_sid(), email="paul@example.com",)
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

    user1 = User(
        username="straw_berry",
        sid=generate_sid(),
        email="strawberry8@example.com",
    )
    user1.set_password("EJew@MHHQ7x-g.4<")
    user2 = User(
        username="josh_9", sid=generate_sid(), email="josh+otpapp@gmail.com",
    )
    user2.set_password("m7ZTbjQdwuUFU/Zy6la+k6uUtniBExIgEhmBPduKexM=")
    user3 = User(
        username="dave", sid=generate_sid(), email="dave16@outlook.com",
    )
    user3.set_password("wselfknskjdksdaiujlj")
    db.session.add(user1)
    db.session.add(user2)
    db.session.add(user3)

    user4 = User(username="mark", sid=generate_sid(), email="mark@gmail.com",)
    user4.set_password("c1c149afbf4c8996fb92427ae41e4649b934ca")

    user5 = User(
        username="jennie", sid=generate_sid(), email="jennie@gmail.com",
    )
    user5.set_password("9df1c362e4df3e51edd1acde9")
    db.session.add(user4)
    db.session.add(user5)
    db.session.commit()

    got_user4 = User.query.filter_by(username="mark").first()
    webauthn_for_user4 = Webauthn(
        number=0, is_enabled=True, user_id=got_user4.did
    )

    db.session.add(webauthn_for_user4)

    db.session.commit()

    yield db

    db.drop_all()
