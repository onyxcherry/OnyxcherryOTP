# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

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
from fido2.ctap2 import (
    AttestationObject,
    AttestedCredentialData,
    AuthenticatorData,
)
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


def get_credential_data(user_database_id: int) -> dict:
    webauthn = Webauthn.query.filter_by(user_id=user_database_id).first()
    if webauthn and webauthn.credentials:
        credential_blob = webauthn.credentials
        credential_data = cbor.decode(base64.b64decode(credential_blob))
    else:
        credential_data = {}
    return credential_data


def get_credentials(user_database_id: int) -> list:
    credential_data = get_credential_data(user_database_id)
    encoded_keys = list(credential_data)
    if not encoded_keys:
        return []
    decoded_keys = [cbor.decode(k) for k in encoded_keys]
    credentials = make_credentials_from_data_second(decoded_keys)
    return credentials


def encode_credentials_data_to_store(credential_data: dict) -> str:
    return base64.b64encode(cbor.encode(credential_data))


def make_credentials_from_data_second(data: list) -> list:
    credentials = []
    for d in data:
        obj = AttestedCredentialData.create(
            d["aaguid"], d["credential_id"], d["public_key"],
        )
        credentials.append(obj)
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

    credentials = get_credentials(user_database_id)

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
    client_data = ClientData(data["clientDataJSON"])
    att_obj = AttestationObject(data["attestationObject"])

    auth_data = server.register_complete(
        session["state"], client_data, att_obj
    )

    creds_parameters = {
        "aaguid": auth_data.credential_data.aaguid,
        "credential_id": auth_data.credential_data.credential_id,
        "public_key": auth_data.credential_data.public_key,
    }

    credential_data = get_credential_data(database_id)
    credential_data[cbor.encode(creds_parameters)] = str(datetime.utcnow())

    webauthn_data = Webauthn.query.filter_by(user_id=database_id).first()

    if not webauthn_data:

        webauthn_data = Webauthn(
            number=0, credentials="", is_enabled=False, user_id=database_id
        )
        db.session.add(webauthn_data)
        db.session.commit()
        webauthn_data = Webauthn.query.filter_by(user_id=database_id).first()

    webauthn_data.credentials = encode_credentials_data_to_store(
        credential_data
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

    credentials = get_credentials(database_id)
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

    credentials = get_credentials(database_id)
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

    for cred in credentials:
        if cred.credential_id == credential_id:
            cred_parameters = {
                "aaguid": cred.aaguid,
                "credential_id": cred.credential_id,
                "public_key": cred.public_key,
            }
            encoded_key = cbor.encode(cred_parameters)
            credential_data = get_credential_data(database_id)
            credential_data[encoded_key] = str(datetime.utcnow())
            break

    webauthn.credentials = encode_credentials_data_to_store(credential_data)
    db.session.add(webauthn)
    db.session.commit()

    login_user(user, remember=remember_me)

    return cbor.encode({"status": "OK"})
