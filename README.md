# OnyxcherryOTP
## Flask (Python) app with two-factor authentication based on time - [One-Time password](https://en.wikipedia.org/wiki/One-time_password).

### Features
* Sign in, register panels
* Fresh login requirement to crucial operations
* Reset password by email
* Activate and deactivate 2FA
* Two latest OTP are valid
* QR Code rendered at client-side (by a pure Javascript library)
* Easy translations with Flask-Babel

#### Since client get only secret code (asynchronous), it is no need to deal with images and its caching by robots etc.

#### Two latest OTP are valid in order to transfer limits and to improve usability.
pyotp library allows to generate and check OTP at given time, e.g. for last 30 seconds:
`totp.at(datetime.datetime.now()-timedelta(seconds=30))`

### Install
1. Clone this repository
```bash
git clone https://github.com/onyxcherry/OnyxcherryOTP.git 
```
2. Create and activate python virtual environment
```bash
cd OnyxcherryOTP
python3 -m venv venv
source venv/bin/activate
```
3. Install dependencies
```bash
pip install -r requirements.txt
```
4. Create database
> This project uses sqlite3. You could use anything else.

```bash
flask shell
```
```python3
>>> db.create_all()
```
5. Generate and change app's secrets. Use
```bash
python -c 'from os import urandom; from base64 import b64encode; print(b64encode(urandom(32)).decode("utf-8"))'
```
and change secrets in .env and in config.py to the generated above.

> WARNING: app is running on development environment

OnyxcherryOTP uses SendGrid to sending emails. Set `MAIL_LOCALHOST=True` in the .env if you want to send emails to localhost. Type `python3 -m smtpd -n -c DebuggingServer localhost:8465` in another console window.

### TO-DO:
* Add Captcha
* Temporarily block user account due to security reasons (and sign in through email)
* Add `revoke other sessions` button
* Add alternative way to 2FA authenticate (backup codes)
* Deploy in production

### Credits:
* [Miguel's incredible Flask tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)
* [QR Code svg generator](https://github.com/datalog/qrcode-svg) – client-side, pure Javascript
