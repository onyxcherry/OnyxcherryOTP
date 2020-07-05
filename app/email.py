import os
from threading import Thread

from flask import current_app
from flask_mail import Message

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from app import mail


def send_async_email(app, msg):
    with app.app_context():
        mail.send(msg)

def send_email(subject, sender, sender_name, recipients, text_body, html_body):
    if os.environ.get('MAIL_LOCALHOST') is not None:
        msg = Message(subject, sender=sender, recipients=recipients)
        msg.body = text_body
        msg.html = html_body
        Thread(target=send_async_email,
                args=(current_app._get_current_object(), msg)).start()
        return

    message = Mail(
        from_email=(sender, sender_name),
        to_emails=recipients,
        subject=subject,
        html_content=html_body)
    try:
        sendgrid_client = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        response = sendgrid_client.send(message)
        print(response.status_code)
        print(response.body)
        print(response.headers)
    except Exception as e:
        print(e)
        print(e.body)
