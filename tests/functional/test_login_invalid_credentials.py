from helping import sign_in


def test_login_without_2fa(test_client, init_database):
    login_response = sign_in(
        test_client,
        "non_existing_user_hasjdbhjbsdjmhd",
        "doisajcklanms632dxmsandu5r4iwe",
    )
    assert (
        b"Hello, non_existing_user_hasjdbhjbsdjmhd" not in login_response.data
    )
