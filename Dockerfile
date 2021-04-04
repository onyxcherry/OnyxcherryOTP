FROM debian:buster-slim as builder

RUN apt-get -qq update && \
    apt-get install -qq --yes --no-install-suggests --no-install-recommends python3-venv gcc libpython3-dev git && \
    python3 -m venv /venv && /venv/bin/pip install --upgrade pip

RUN git clone https://github.com/onyxcherry/OnyxcherryOTP.git /code
RUN /venv/bin/pip install --disable-pip-version-check -r /code/requirements.txt && \
    /venv/bin/pip install --disable-pip-version-check gunicorn==20.0.4 psycopg2-binary==2.8.6

ENV PATH="/venv/bin:$PATH"
ENV FLASK_APP=/code/onyxcherryotp.py
WORKDIR /code
RUN /venv/bin/flask translate compile


FROM gcr.io/distroless/python3-debian10

COPY --from=builder /code/app /code/app
COPY --from=builder /code/config.py /code/config.py
COPY --from=builder /code/babel.cfg /code/babel.cfg
COPY --from=builder /code/setup.py /code/setup.py
COPY --from=builder /code/onyxcherryotp.py /code/onyxcherryotp.py
COPY --from=builder /venv /venv

WORKDIR /code

EXPOSE 5777

ENTRYPOINT ["/venv/bin/python3", "/venv/bin/gunicorn", "-b", ":5777", "--chdir", "/code", "--reload", "--access-logfile", "-", "--error-logfile", "-", "onyxcherryotp:app"]
