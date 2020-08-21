def test_unauthorized_request(test_client, init_database):
    response = test_client.get('/auth/generate_token', follow_redirects=True)
    assert b'Please log in to access this page.' in response.data