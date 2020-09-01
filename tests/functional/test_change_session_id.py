from app.models import User
from helping import delete_session_cookie, get_index, sign_in_no_fr


def test_change_session_id(test_client, init_database):
    response = sign_in_no_fr(test_client, "dave", "wselfknskjdksdaiujlj")
    session_header = response.headers.get("Set-Cookie")
    old_session = session_header.split()[0].split("=")[1]
    change_session_id_response = test_client.get("/auth/change_session")
    checking_response = get_index(test_client)
    assert b"Hello, dave" in checking_response.data
    delete_session_cookie(test_client)
    test_client.set_cookie(
        server_name="localhost", key="session", value=old_session
    )
    old_session_response = get_index(test_client)
    assert b"Hello, dave" not in old_session_response.data
    assert b"Please log in to access this page." in old_session_response.data