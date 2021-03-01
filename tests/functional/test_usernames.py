from helping import register


def test_case_insensitive_user_register(test_client, init_database):
    resp = register(
        test_client,
        username="JoSh_9",
        email="indeed_not_existing_basdjhbsajkhfbsahj345undsccm@example.org",
        password="somethingsecure",
        password2="somethingsecure",
    )
    assert b"Please use a different username" in resp.data
