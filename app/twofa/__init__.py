from flask import Blueprint

bp = Blueprint("twofa", __name__)

from app.twofa import routes
