import asyncio
import os
from threading import Thread

from flask import current_app
from flask_mail import Message
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Content, From, Mail, To

from app import mail


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_email(subject, sender, sender_name, recipients, text_body, html_body):
    if os.environ.get("MAIL_LOCALHOST") is not None:
        msg = Message(subject, sender=sender, recipients=recipients)
        msg.body = text_body
        msg.html = html_body
        Thread(
            target=send_async_email,
            args=(current_app._get_current_object(), msg),
        ).start()
        return

    sendgrid_client = SendGridAPIClient(
        api_key=os.environ.get("SENDGRID_API_KEY")
    )
    from_email = From(sender, sender_name)
    to_email = To(recipients)
    plain_text_content = Content("text/plain", text_body)
    html_content = Content("text/html", html_body)
    em = Mail(from_email, to_email, subject, html_content)
    asyncio.run(async_send_mail(em, sendgrid_client))


async def async_send_mail(email, sendgrid_client):
    try:
        response = sendgrid_client.send(email)
        if response.status_code < 300:
            print(
                "Send email",
                response.status_code,
                response.headers,
                response.body,
            )
    except Exception as e:
        print(e)
