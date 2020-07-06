from app import cli, create_app, db
from app.models import OTP, User, ResetPasswordValue

app = create_app()
cli.register(app)

@app.shell_context_processor
def make_shell_context():
    return {'db': db, 'User': User, 'OTP': OTP, 'ResetPasswordValue': ResetPasswordValue}