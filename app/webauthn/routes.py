from __future__ import absolute_import, print_function, unicode_literals

import base64
import uuid
from datetime import datetime

from app import db
from app.models import User, Webauthn
from app.webauthn import bp
from config import Config
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AuthenticatorData
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_babel import _
from flask_babel import lazy_gettext as _l
from flask_login import (
    current_user,
    fresh_login_required,
    login_required,
    login_user,
)
from werkzeug.urls import url_parse

rp = PublicKeyCredentialRpEntity(Config.RP_ID, "Demo server")
server = Fido2Server(rp)


def get_next_page(next_from_request: str) -> str:
    next_page = next_from_request
    if not next_page or url_parse(next_page).netloc != "":
        next_page = url_for("main.index")
    return next_page


def get_user_credential_data(user_database_id: int) -> dict:
    webauthn = Webauthn.query.filter_by(user_id=user_database_id).first()
    if webauthn and webauthn.credentials:
        credential_blob = webauthn.credentials
        credential_data = cbor.decode(base64.b64decode(credential_blob))
    else:
        credential_data = {}
    return credential_data


def get_credential_data_to_store(credential_data: dict) -> str:
    encoded_credentials = cbor.encode(credential_data)
    data_to_store_in_database = base64.b64encode(encoded_credentials)
    return data_to_store_in_database


def make_credentials_from_data(data: list) -> list:
    credentials = []
    for d in data:
        credentials.append(AttestationObject(d).auth_data.credential_data)
    return credentials


@bp.route("/")
def index():
    return render_template("webauthn/overview.html", webauthn_enabled=False)


@bp.route("/check")
@fresh_login_required
def check():
    return render_template("webauthn/authenticate.html")


@bp.route("/activate")
@login_required
@fresh_login_required
def activate():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    webauthn = Webauthn.query.filter_by(user_id=database_id).first()

    # alternatively we should allow in case when one key added and backup codes
    if webauthn and webauthn.credentials and webauthn.number >= 2:
        webauthn.is_enabled = True
        db.session.add(webauthn)
        db.session.commit()
        flash(_("Enabled Webauthn!"))
        return render_template("index.html")

    else:
        webauthn = Webauthn.query.filter_by(user_id=database_id).first()
        flash(_("You have to register the keys before"))
        return render_template("webauthn/register.html")


@bp.route("/management")
@fresh_login_required
def manage_keys():
    return "Your keys: TO-DO"


@bp.route("/register/begin", methods=["POST"])
@fresh_login_required
def register_begin():
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    user = User.query.filter_by(did=user_database_id).first()
    username = user.username

    credential_data = get_user_credential_data(user_database_id)
    credential_blob = list(credential_data)
    credentials = make_credentials_from_data(credential_blob)

    webauthn_user_id = uuid.uuid4().hex.encode()

    registration_data, state = server.register_begin(
        {
            "id": webauthn_user_id,
            "name": username,
            "displayName": f"OnyxcherryAuthn demo - {username}",
            "icon": "https://example.com/image.png",
        },
        credentials,
        user_verification="discouraged",
        authenticator_attachment="cross-platform",
    )

    session["state"] = state

    return cbor.encode(registration_data)


@bp.route("/register/complete", methods=["POST"])
@fresh_login_required
def register_complete():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)

    data = cbor.decode(request.get_data())
    print(data)
    blob_to_save = data["attestationObject"]
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])

    auth_data = server.register_complete(
        session["state"], client_data, att_obj
    )

    user_credential_data = get_user_credential_data(database_id)
    user_credential_data[blob_to_save] = str(datetime.utcnow())
    webauthn_data = Webauthn.query.filter_by(user_id=database_id).first()
    if not webauthn_data:
        webauthn_data = Webauthn(
            number=0, credentials="", is_enabled=False, user_id=database_id
        )
        db.session.add(webauthn_data)
        db.session.commit()
        webauthn_data = Webauthn.query.filter_by(user_id=database_id).first()
    webauthn_data.credentials = get_credential_data_to_store(
        user_credential_data
    )
    if webauthn_data.number <= 10:
        webauthn_data.number += 1
        db.session.add(webauthn_data)
        db.session.commit()
        return cbor.encode({"status": "OK"})
    else:
        return cbor.encode(
            {"status": "error", "reason": "Too much keys registered"}
        )


@bp.route("/authenticate/begin", methods=["POST"])
def authenticate_begin():
    token = request.cookies.get("token")
    if not token:
        abort(401)
    username, remember_me = User.verify_twofa_login_token(token.encode())
    if not username:
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    database_id = user.did

    user_credential_data = get_user_credential_data(database_id)
    credentials_blob = list(user_credential_data)
    credentials = make_credentials_from_data(credentials_blob)

    if not credentials:
        abort(401)

    auth_data, state = server.authenticate_begin(credentials, "discouraged")
    session["state"] = state

    return cbor.encode(auth_data)


@bp.route("/authenticate/complete", methods=["POST"])
def authenticate_complete():
    token = request.cookies.get("token")
    if not token:
        abort(401)
    username, remember_me = User.verify_twofa_login_token(token.encode())
    if not username:
        flash(_("Invalid token!"))
        return redirect(url_for("auth.login"))
    user = User.query.filter_by(username=username).first()
    database_id = user.did

    user_credential_data = get_user_credential_data(database_id)
    credentials_blob = list(user_credential_data)
    credentials = make_credentials_from_data(credentials_blob)

    if not credentials:
        abort(401)

    data = cbor.decode(request.get_data())

    credential_id = data["credentialId"]
    client_data = ClientData(data["clientDataJSON"])
    auth_data = AuthenticatorData(data["authenticatorData"])
    signature = data["signature"]

    server.authenticate_complete(
        session.pop("state"),
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature,
    )

    webauthn = Webauthn.query.filter_by(user_id=database_id).first()
    for cred in credentials_blob:
        if (
            credential_id
            == AttestationObject(cred).auth_data.credential_data.credential_id
        ):
            user_credential_data[cred] = str(datetime.utcnow())
            webauthn.credentials = get_credential_data_to_store(
                user_credential_data
            )
            db.session.add(webauthn)
            db.session.commit()
            break

    login_user(user, remember=remember_me)

    return cbor.encode({"status": "OK"})
