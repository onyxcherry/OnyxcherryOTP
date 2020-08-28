from app.email import send_email
from flask import current_app, render_template
from flask_babel import _


def send_password_reset_email(user, token):
    send_email(
        _("[Onyxcherry OTP] Reset Your Password"),
        sender_email=current_app.config["ADMINS"][0],
        sender_name="OnyxcherryOTP",
        recipients=[user.email],
        text_body=render_template(
            "email/reset_password.txt", user=user, token=token
        ),
        html_body=render_template(
            "email/reset_password.html", user=user, token=token
        ),
    )
