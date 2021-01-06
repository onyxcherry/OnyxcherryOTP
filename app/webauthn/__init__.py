from flask import Blueprint

bp = Blueprint("webauthn", __name__)

from app.webauthn import routes
