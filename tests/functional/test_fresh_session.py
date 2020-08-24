def test_double_fresh_session(test_client, init_database):
    test_client.set_cookie(
        server_name="127.0.0.1",
        key="session",
        value=".eJwlzsENwzAIAMBd_O4DbMAmy0RgsNJv0ryq7t5KvQnuXfZ15nWU7XXe-Sj7M8"
        "pWAGoIjdErL6xdWYg9zA2bSTN11YoeYIYS2RWmhCpZxcF9kVCrTTnD6kpzXAQBRGI0RQl"
        "mD1zMTiM6rGQ3UXQ0G5NhgqKUX-S-8vxvsHy-Zu8ulw.Xz92Mg.mQrA3dwCAV5oCoo14U"
        "vJbNunAVY",
    )
    response = test_client.get("/auth/activate_2fa", follow_redirects=True)

    assert b"You are activating two factor authentication." in response.data
