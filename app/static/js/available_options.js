const webauthn_button = document.getElementById('webauthn-button')
const otp_button = document.getElementById('otp-button')
const backup_code_button = document.getElementById('backup-code-button')

webauthn_button.addEventListener('click', () => {
    window.location = '/auth/use_webauthn';
})
otp_button.addEventListener('click', () => {
    window.location = '/auth/use_otp';
})