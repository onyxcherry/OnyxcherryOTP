import asyncio
import os
import smtplib
from email.mime.text import MIMEText

from config import Config, setup_logger
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Content, From, Mail, To

email_logger = setup_logger("email_logger", "email.log")


def send_email_localhost(
    subject, sender_email, sender_name, recipient, text_body, html_body
):
    msg = MIMEText(text_body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = recipient

    with smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT) as server:
        server.sendmail(sender_email, recipient, msg.as_string())


def send_real_email(
    subject, sender, sender_name, recipients, text_body, html_body
):
    sendgrid_client = SendGridAPIClient(
        api_key=os.environ.get("SENDGRID_API_KEY")
    )
    from_email = From(sender, sender_name)
    to_email = To(recipients)
    Content("text/plain", text_body)
    html_content = Content("text/html", html_body)
    em = Mail(from_email, to_email, subject, html_content)
    asyncio.run(send_email_sendgrid(em, sendgrid_client))


def send_email(*args, **kwargs):
    if os.environ.get("MAIL_LOCALHOST"):
        send_email_localhost(*args, **kwargs)
    else:
        send_real_email(*args, **kwargs)


async def send_email_sendgrid(email, sendgrid_client):
    try:
        response = sendgrid_client.send(email)
        if response.status_code < 300:
            email_logger.info(
                f"Sent email {response.status_code} "
                f"{response.headers} {response.body}"
            )
    except Exception as e:
        email_logger.error(e)
