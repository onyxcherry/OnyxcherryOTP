FROM python:3.8.5-slim-buster

RUN adduser --disabled-password --gecos "" onyxcherry
WORKDIR /home/onyxcherry

RUN apt-get -qq update && \
    apt-get install -qq -y --no-install-recommends git

RUN git clone https://github.com/onyxcherry/OnyxcherryOTP.git
WORKDIR /home/onyxcherry/OnyxcherryOTP

RUN python -m venv venv
RUN venv/bin/pip install -r requirements.txt
RUN venv/bin/pip install gunicorn psycopg2-binary flask-migrate

RUN chmod +x boot.sh

ENV FLASK_APP onyxcherryotp.py

RUN chown -R onyxcherry:onyxcherry ./
USER onyxcherry

EXPOSE 5777

ENTRYPOINT [ "./boot.sh" ]
