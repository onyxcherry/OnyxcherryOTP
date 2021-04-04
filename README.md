# OnyxcherryOTP

## Flask (Python) app with two-factor authentication based on time - [One-Time password](https://en.wikipedia.org/wiki/One-time_password).

### Features

* Sign in, register, reset password panels
* Fresh (can be refreshed) session requirement for crucial operations
* Reset password by email
* Webauthn 2FA, including resident key
* Activate and deactivate 2FA
* Two latest OTP codes are valid
* QR Code rendered at client-side (by a pure Javascript library)
* Easy translations with Flask-Babel
* Content Security Policy Level 3
* Distroless production app container

## Running

> Whether or not development purpose, you have to run the app with https if you want to use Webauthn!

The following applies to all methods:

* Copy `sample.env` to `.env` and fill it in according to your needs. [More about environment](https://github.com/onyxcherry/OnyxcherryOTP#note-about-environment-variables)

### Manually (test-purposes only)

1. Clone this repository

``` bash
git clone https://github.com/onyxcherry/OnyxcherryOTP.git
```

2. Create and activate python virtual environment

``` bash
cd OnyxcherryOTP
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies

``` bash
pip install -r requirements.txt
```

and - if you are a developer - also `requirements.dev` .

4. Compile translations

``` bash
flask translate compile
```

5. Create database

> This project uses sqlite3 by default for the convenience. You could use anything else.

> You don't need to run Redis - it can be instantiated by Fake-redis module.

``` bash
$ flask shell

>>> db.create_all()
```

If you use a real database (such as Postgres), remember to specify a url (as `DATABASE_URL` ) to it in `.env` and create database so named **before**.

6. Run

``` bash
flask run
```

or use [Gunicorn](https://gunicorn.org/):

* Generate own self-signed SSL certs with [mkcert](https://github.com/FiloSottile/mkcert) or [openssl](https://devcenter.heroku.com/articles/ssl-certificate-self), 

* Run the app with https:

``` bash
gunicorn --bind 127.0.0.1:5777:5777 --certfile /path/to/server.crt --keyfile /path/to/server.key --access-logfile - --error-logfile - --reload onyxcherryotp:app
```

### Docker-compose

As the container shouldn't manage the database schema, remember to create database named `onyxcherryotp` (see `DATABASE_URL` environment variable in docker-compose) and create schema:

``` bash
$ flask shell

>>> db.create_all()
```

#### Production

``` bash
docker-compose up
```

#### Development

``` bash
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
```

Simply edit code - changes will be applied in a container by auto-reloading Gunicorn.

If you encounter a problem in a production container (distroless image), add `:debug` to last-stage image (last `FROM` ) tag and get into `/bin/sh` (rebuild image before).

## Note about environment variables

Both Gunicorn (due to at least 2 workers) and Docker needs to specify **same** environment variables, especially `SECRET_KEY` . Unless specified, you will have troubles with correctly cookies' sign.

If you has already generated ReCAPTCHA keys, pass it:

* `RECAPTCHA_PUBLIC_KEY` as environment variable
* `RECAPTCHA_PRIVATE_KEY` as secret 

**Update other variables**.

### Secrets

In order to keep the app safe, pass secret values as Docker Swarm Secrets or use external software (specify _external_ to _true_ in docker-compose.yml).

As PoC you could create files named `secret_*` ( `secret_secret_key` , `secret_twofa_secret_key` , `secret_sendgrid_api_key` ) and there keep secret values.
These files are ignored by Git (they are in .gitignore).

#### Random values

Therefore use e.g

``` bash
python -c 'from os import urandom; from base64 import b64encode; print(b64encode(urandom(32)).decode("utf-8"))'
```

## Testing

``` bash
pytest
```

(you might need to type `pip install -e .` )

---

OnyxcherryOTP uses SendGrid to sending emails. Set `MAIL_LOCALHOST=True` in the .env if you want to send emails to the localhost.

If so type 

``` bash
python3 -m smtpd -n -c DebuggingServer localhost:8465
```

in another console window and reveive emails sent to localhost.

## TO-DO:

* [x] Add `revoke other sessions` button
* [x] Add custom front-end (panels)
* [ ] Temporarily block user account due to security reasons (and verify & sign in through email)
* [ ] Add alternative way to 2FA authenticate (backup codes)
* [x] Add WebAuthn 

## Credits:

* [Miguel's incredible Flask tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)
* [QR Code svg generator](https://github.com/datalog/qrcode-svg) – client-side, pure Javascript
* [Bootstrap pretty forms](https://www.bootstrapdash.com/product/free-bootstrap-login/)
* [Bootstrap Cover theme](https://getbootstrap.com/docs/4.5/examples/cover/)
* [Webauthn developer guide](https://developers.yubico.com/WebAuthn/)
* [Webauthn logo](https://github.com/samuelweiler/webauthn-logos)
