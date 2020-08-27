FROM python:3.8.5-slim-buster

RUN adduser --disabled-password onyxcherry
WORKDIR /home/onyxcherry

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y git
RUN git clone https://github.com/onyxcherry/OnyxcherryOTP.git
WORKDIR /home/onyxcherry/OnyxcherryOTP
RUN python -m venv venv && pip install psycopg2-binary gunicorn flask-migrate && pip install -r requirements.txt
RUN chmod +x boot.sh

ENV FLASK_APP onyxcherryotp.py

RUN chown -R onyxcherry:onyxcherry ./
USER onyxcherry

EXPOSE 5777

ENTRYPOINT [ "./boot.sh" ]
