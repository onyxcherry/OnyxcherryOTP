FROM python:3.9.1-slim-buster as builder

RUN adduser --disabled-password --gecos "" onyxcherry
WORKDIR /home/onyxcherry

RUN apt-get -qq update && \
    apt-get install -qq -y --no-install-recommends git

RUN git clone https://github.com/onyxcherry/OnyxcherryOTP.git
WORKDIR /home/onyxcherry/OnyxcherryOTP

RUN python -m venv venv && \
    venv/bin/pip install --no-cache-dir -r requirements.txt && \
    venv/bin/pip install --no-cache-dir  gunicorn==20.0.4

RUN venv/bin/pip install --no-cache-dir psycopg2-binary


FROM python:3.9.1-slim-buster

RUN adduser --disabled-password --gecos "" onyxcherry

WORKDIR /home/onyxcherry/OnyxcherryOTP

COPY --from=builder /home/onyxcherry/OnyxcherryOTP/app app
COPY --from=builder /home/onyxcherry/OnyxcherryOTP/venv venv
COPY --from=builder /home/onyxcherry/OnyxcherryOTP/boot.sh .
COPY --from=builder /home/onyxcherry/OnyxcherryOTP/babel.cfg .
COPY --from=builder /home/onyxcherry/OnyxcherryOTP/setup.py .
COPY --from=builder /home/onyxcherry/OnyxcherryOTP/onyxcherryotp.py .

RUN chmod +x boot.sh

ENV FLASK_APP onyxcherryotp.py

RUN chown -R onyxcherry:onyxcherry ./
USER onyxcherry

EXPOSE 5777

ENTRYPOINT [ "./boot.sh" ]
