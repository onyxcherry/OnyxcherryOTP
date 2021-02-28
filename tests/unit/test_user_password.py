import pytest


@pytest.mark.skip(reason="Hashing password takes too much time")
def test_user_password_hashing(user):
    sample_password = "12paul%47"
    user.set_password(sample_password)
    assert user.check_password(sample_password) is True
