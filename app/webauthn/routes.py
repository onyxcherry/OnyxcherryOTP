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

import binascii
import hashlib
import json
import os
from datetime import datetime
from typing import Tuple

from app import db
from app.models import Key, User, Webauthn
from app.webauthn import bp
from app.webauthn.forms import DeleteKey, NameKey
from config import Config
from fido2 import cbor
from fido2.attestation import Attestation, InvalidSignature
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
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_babel import _
from flask_babel import lazy_gettext as _l  # noqa: F401
from flask_login import (
    current_user,
    fresh_login_required,
    login_required,
    login_user,
)

rp = PublicKeyCredentialRpEntity(Config.RP_ID, "Demo server")
server = Fido2Server(rp, attestation=Config.ATTESTATION)


def get_credentials(user_database_id: int) -> list:
    current_keys = Key.query.filter_by(user_id=user_database_id).all()
    credentials = []
    for key in current_keys:
        obj = AttestedCredentialData.create(
            key.aaguid, key.credential_id, cbor.decode(key.public_key)
        )
        credentials.append(obj)
    return credentials


def get_current_user_info(token: str, user_identity: str) -> Tuple[int, bool]:
    if user_identity is not None:
        database_id = User.get_database_id(user_identity)
        return (database_id, False)

    if token is not None:
        username, remember_me = User.verify_twofa_login_token(token.encode())
        user = User.query.filter_by(username=username).first()
        database_id = user.did
        return (database_id, remember_me)


@bp.route("/")
@login_required
def index():
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    webauthn = Webauthn.query.filter_by(user_id=user_database_id).first()
    if webauthn is not None:
        webauthn_is_enabled = webauthn.is_enabled
    else:
        webauthn_is_enabled = False

    return render_template(
        "webauthn/overview.html", webauthn_enabled=webauthn_is_enabled
    )


@bp.route("/check")
@fresh_login_required
def check():
    return render_template("webauthn/login_with_webauthn.html")


@bp.route("/keys/add")
@fresh_login_required
def add_key():
    return render_template("webauthn/register.html")


@bp.route("/keys/manage")
@fresh_login_required
def manage_keys():
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    webauth = Webauthn.query.filter_by(user_id=user_database_id).first()
    any_keys = False
    if webauth is not None and webauth.number > 0:
        any_keys = True
    return render_template("webauthn/manage_keys.html", any_keys=any_keys)


@bp.route("/keys/list")
@login_required
def list_keys():
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    keys = Key.query.filter_by(user_id=user_database_id).all()
    resp = {}
    for key in keys:
        o = {"name": key.name, "last_access": key.last_access}
        resp[binascii.b2a_hex(key.credential_id).decode()] = o
    return jsonify(resp)


@bp.route("/verify_attestation/<credential_id>")
@login_required
def verify_attestation(credential_id):
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    resp = {}
    keys = Key.query.filter_by(user_id=user_database_id).all()
    for key in keys:
        decoded_attestation = cbor.decode(key.attestation)
        statement = decoded_attestation["attStmt"]
        auth_data = AuthenticatorData(decoded_attestation["authData"])
        client_data_hash = key.client_data_hash
        fmt = decoded_attestation["fmt"]
        obtain_att = Attestation.for_type(fmt)
        att = obtain_att()
        try:
            att.verify(statement, auth_data, client_data_hash)
        except InvalidSignature:
            resp[binascii.b2a_hex(key.credential_id).decode()] = "ERROR"
        finally:
            resp[binascii.b2a_hex(key.credential_id).decode()] = "OK"
    return jsonify(resp)


@bp.route("/keys/name/<credential_id>")
@fresh_login_required
def render_key_name(credential_id):
    form = NameKey()
    return render_template(
        "webauthn/name_key.html", form=form, credential_id=credential_id
    )


@bp.route("/keys/name", methods=["POST"])
@fresh_login_required
def name_key():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    form = NameKey()
    if form.validate_on_submit():
        credential_id = form.credential_id.data
        new_key_name = form.key_name.data
        webauthn_key = (
            Key.query.filter_by(user_id=database_id)
            .filter_by(credential_id=binascii.a2b_hex(credential_id))
            .first()
        )
        if webauthn_key is None:
            abort(401)
        webauthn_key.name = new_key_name
        db.session.add(webauthn_key)
        db.session.commit()
        flash(_("Correctly!"))
        return redirect(url_for("webauthn.index"))
    abort(401)


@bp.route("/keys/delete/<credential_id>")
@fresh_login_required
def render_key_delete(credential_id):
    form = DeleteKey()
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    webauth = Webauthn.query.filter_by(user_id=user_database_id).first()
    if webauth.number == 1:
        flash(
            _(
                "Deleting the key causes deactivating Webauthn "
                "for your account!"
            )
        )
    short_credential_id = credential_id[:12]

    return render_template(
        "webauthn/delete_key.html",
        form=form,
        credential_id=credential_id,
        short_credential_id=short_credential_id,
    )


@bp.route("/keys/delete", methods=["POST"])
@fresh_login_required
def delete_key():
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    form = DeleteKey()
    if form.validate_on_submit():
        credential_id = form.credential_id.data
        key_to_delete = (
            Key.query.filter_by(user_id=user_database_id)
            .filter_by(credential_id=binascii.a2b_hex(credential_id))
            .first()
        )
        if key_to_delete is None:
            abort(401)
        db.session.delete(key_to_delete)
        webautn = Webauthn.query.filter_by(user_id=user_database_id).first()
        webautn.number -= 1
        db.session.add(webautn)
        db.session.commit()
        flash(_("Deleted!"))
        return redirect(url_for("webauthn.index"))
    abort(401)


@bp.route("/activate")
@fresh_login_required
def activate():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    webauthn = Webauthn.query.filter_by(user_id=database_id).first()

    # alternatively we should allow in case when one key added and backup codes
    if webauthn and webauthn.number >= 2:
        webauthn.is_enabled = True
        db.session.add(webauthn)
        db.session.commit()
        flash(_("Enabled Webauthn!"))
        return render_template("index.html")
    else:
        flash(_("You have to register keys before"))
        return redirect(url_for("webauthn.add_key"))


@bp.route("/deactivate")
@fresh_login_required
def deactivate():
    user_id = current_user.get_id()
    database_id = User.get_database_id(user_id)
    webauthn = Webauthn.query.filter_by(user_id=database_id).first()

    if webauthn is not None and webauthn.is_enabled is True:
        webauthn.is_enabled = False
        db.session.add(webauthn)
        db.session.commit()
        flash(_("Deactivated webauthn!"))
    return redirect(url_for("webauthn.index"))


@bp.route("/register/begin", methods=["POST"])
@fresh_login_required
def register_begin():
    user_id = current_user.get_id()
    user_database_id = User.get_database_id(user_id)
    user = User.query.filter_by(did=user_database_id).first()
    username = user.username
    database_id = user.did

    credentials = get_credentials(user_database_id)

    is_resident = json.loads(request.data)["resident"]

    webauthn_data = Webauthn.query.filter_by(user_id=database_id).first()

    if webauthn_data is None:
        user_identifier = b"\x7e" + os.urandom(31)
        webauthn_data = Webauthn(
            number=0,
            is_enabled=False,
            user_identifier=user_identifier,
            user_id=database_id,
        )
        db.session.add(webauthn_data)
        db.session.commit()

    user_identifier = webauthn_data.user_identifier

    registration_data, state = server.register_begin(
        {
            "id": user_identifier,
            "name": username,
            "displayName": f"OnyxcherryAuthn demo - {username}",
            "icon": "https://example.com/image.png",
        },
        credentials,
        resident_key=is_resident,
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

    webauthn_data = Webauthn.query.filter_by(user_id=database_id).first()

    new_key = Key(
        name=f"Key {webauthn_data.number + 1}",
        aaguid=auth_data.credential_data.aaguid,
        credential_id=auth_data.credential_data.credential_id,
        client_data_hash=hashlib.sha256(client_data).digest(),
        public_key=cbor.encode(auth_data.credential_data.public_key),
        counter=att_obj.auth_data.counter,
        attestation=data["attestationObject"],
        info="TODO",
        last_access=datetime.utcnow(),
        created=datetime.utcnow(),
        user_id=database_id,
    )

    if webauthn_data.number <= 10:
        webauthn_data.number += 1
        db.session.add(webauthn_data)
        db.session.add(new_key)
        db.session.commit()
        return cbor.encode({"status": "OK"})
    else:
        flash(_("Too much keys registered"))
        return (
            cbor.encode(
                {"status": "error", "reason": "Too much keys registered"}
            ),
            401,
        )


@bp.route("/authenticate/begin", methods=["POST"])
def authenticate_begin():
    token = request.cookies.get("token")
    user_identity = current_user.get_id()
    database_id, _ = get_current_user_info(token, user_identity)

    if database_id is None:
        abort(401)

    credentials = get_credentials(database_id)
    if not credentials:
        abort(401)

    auth_data, state = server.authenticate_begin(credentials, "discouraged")
    session["state"] = state

    return cbor.encode(auth_data)


@bp.route("/authenticate/complete", methods=["POST"])
def authenticate_complete():
    token = request.cookies.get("token")
    user_identity = current_user.get_id()
    database_id, remember_me = get_current_user_info(token, user_identity)
    if database_id is None:
        abort(401)

    user = User.query.filter_by(did=database_id).first()

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

    current_counter = int(auth_data.counter)

    keys = Key.query.filter_by(user_id=database_id).all()

    for key in keys:
        if key.credential_id == credential_id:
            last_counter = key.counter
            if last_counter is None or last_counter >= current_counter:
                # Cloned => untrusted key!
                return cbor.encode(
                    {"status": "error", "reason": "invalid counter"}
                )
            key.last_access = datetime.utcnow()
            key.counter = current_counter
            break
    db.session.add(key)
    db.session.commit()

    login_user(user, remember=remember_me)

    return cbor.encode({"status": "OK"})
