# OnyxcherryOTP

## Flask (Python) app with two-factor authentication based on time - [One-Time password](https://en.wikipedia.org/wiki/One-time_password).

### Features

* Sign in, register, reset password panels
* Fresh login requirement to crucial operations
* Reset password by email
* Activate and deactivate 2FA
* Two latest OTP are valid
* QR Code rendered at client-side (by a pure Javascript library)
* Easy translations with Flask-Babel
* Content Security Policy Level 3

#### Since client get only secret code (asynchronous), it is no need to deal with images and its caching by robots etc.

#### Two latest OTP are valid in order to transfer limits and to improve usability.

pyotp library allows to generate and check OTP at given time, e.g. for last 30 seconds:
 `totp.at(datetime.datetime.now()-timedelta(seconds=30))`

### Install

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

4. Compile translations

``` bash
flask translate compile
```

5. Create database

> This project uses sqlite3 by default for the convenience. You could use anything else.

``` bash
flask shell
```

``` python3
>>> db.create_all()
```

### Run
```
flask run
```

or - on production - use [Gunicorn](https://gunicorn.org/).

---
Alternatively - for development - run the app with https (generate own self-signed SSL certs with [mkcert](https://github.com/FiloSottile/mkcert) or [openssl](https://devcenter.heroku.com/articles/ssl-certificate-self)):
```
gunicorn --bind :5777 --certfile /path/to/server.crt --keyfile /path/to/server.key --access-logfile - --error-logfile - --reload onyxcherryotp:app
```

#### Running tests
```
pytest
```
(you might have typed `pip install -e .`)

---

OnyxcherryOTP uses SendGrid to sending emails. Set `MAIL_LOCALHOST=True` in the .env if you want to send emails to localhost.  
Type 

``` 
python3 -m smtpd -n -c DebuggingServer localhost:8465
```

in another console window.

### TO-DO:

* [x] Add `revoke other sessions` button
* [x] Add custom front-end (panels)
* [ ] Temporarily block user account due to security reasons (and verify & sign in through email)
* [ ] Add alternative way to 2FA authenticate (backup codes)
* [ ] Add WebAuthn 

### Credits:

* [Miguel's incredible Flask tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)
* [QR Code svg generator](https://github.com/datalog/qrcode-svg) – client-side, pure Javascript
* [Bootstrap pretty forms](https://www.bootstrapdash.com/product/free-bootstrap-login/)
* [Bootstrap Cover theme](https://getbootstrap.com/docs/4.5/examples/cover/)
* [Webauthn developer guide](https://developers.yubico.com/WebAuthn/)
* [Webauthn logo](https://github.com/samuelweiler/webauthn-logos)
