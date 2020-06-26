from datetime import datetime
from time import time

import jwt
import pyotp
from flask import current_app
from flask_login import UserMixin

from app import bcrypt, db, login
