from helping import generate_token


def test_unauthorized_request(test_client, init_database):
    response = generate_token(test_client)
    assert b"Please log in to access this page." in response.data
