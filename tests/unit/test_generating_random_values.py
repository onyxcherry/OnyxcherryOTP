from app.models import generate_sid


def test_generate_random_values():
    first_value = generate_sid()
    second_value = generate_sid()
    assert first_value != second_value
