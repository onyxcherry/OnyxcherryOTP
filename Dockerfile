FROM python:3.8.5-slim-buster

RUN adduser --disabled-password onyxcherry
WORKDIR /home/onyxcherry

COPY requirements.txt requirements.txt
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y git
RUN python -m venv venv
RUN venv/bin/pip install psycopg2-binary
RUN venv/bin/pip install -r requirements.txt
RUN venv/bin/pip install gunicorn
RUN venv/bin/pip install flask-migrate
COPY app app
COPY migrations migrations
COPY onyxcherryotp.py config.py boot.sh ./
RUN chmod +x boot.sh

ENV FLASK_APP onyxcherryotp.py

RUN chown -R onyxcherry:onyxcherry ./
USER onyxcherry

EXPOSE 5777

ENTRYPOINT [ "./boot.sh" ]
