const userLang = window.navigator.language.split('-')[0]

const base_url = `${window.location.protocol}//${window.location.hostname}:${window.location.port}`

const panel_info = document.querySelector('.panel-info')
const panel_danger = document.querySelector('.panel-danger')
const panel_success = document.querySelector('.panel-success')
const panel_primary = document.querySelector('.panel-primary')
const panel_warning = document.querySelector('.panel-warning')

messages = {
    "otp_info":{
       "en":[
          "Scan the QR and type the code from app below.",
          "Use an OTP app, e.g. Authy or Google Authenticator."
       ],
       "pl":[
          "Zeskanuj poniższy kod QR.",
          "Użyj aplikacji - np. Authy lub Google Authenticator."
       ]
    }
 }

view_as_text_button = document.getElementById('viewAsText')
view_as_qr_button = document.getElementById('viewAsQR')

twofa_qrcode = document.getElementById('2fa-qrcode')

view_as_text_button.addEventListener('click', () => {
    showAsText()
})

view_as_qr_button.addEventListener('click', () => {
    showAsQR()
})

get_token_button = document.getElementById('getTokenButton')
get_token_button.addEventListener('click', () => {
    getToken();
})

check_code_form = document.getElementById('checkCode')
check_code_form.addEventListener('submit', e => {
    submitForm(e, check_code_form)
})

function invalidCode() {
    panel_warning.style.display = 'block';
};

function showAsText() {
    view_as_text_button.style.display = 'none'
    view_as_qr_button.style.display = 'block'
    twofa_qrcode.style.display = 'none'
    panel_primary.style.display = 'block'
}

function showAsQR() {
    view_as_text_button.style.display = 'block'
    view_as_qr_button.style.display = 'none'
    twofa_qrcode.style.display = 'block'
    panel_primary.style.display = 'none'
}

function submitForm(e, form) {
    e.preventDefault();
    fetch(base_url + '/auth/checkcode', {
        method: 'post',
        headers: {
            'Content-Type': 'text/plain'
        },
        body: form.user_code.value
    }).then(response => {
        if (response.ok) {
            return response.text()
        } else {
            errorDiv();
            return Promise.reject(response)
        }
    }).then(response => {
        if (response !== 'OK' && response !== '2FA is enabled.') {
            invalidCode();
        } else {
            document.getElementById('2fa-user-code').style.display = 'none';
            document.getElementById('2fa-qrcode').style.display = 'none';
            panel_success.style.display = 'block'
            panel_info.style.display = 'none'
            panel_danger.style.display = 'none'
        }
    }).catch(err => {
        errorDiv()
    });
}

function errorDiv(m) {
    panel_danger.style.display = 'block';
    console.log(m)
}

function getToken() {
    fetch(base_url + '/auth/generate_token')
        .then(response => {
            if (response.ok) {
                return response.json()
            } else {
                errorDiv();
                return Promise.reject(response)
            }
        })
        .then(response => {
            panel_info.firstElementChild.innerText = messages['otp_info'][userLang][0]
            panel_info.children[1].innerText = messages['otp_info'][userLang][1]
            if (response['app_qrcode']) {
                var svgNode = QRCode(response['app_qrcode'])
            } else {
                errorDiv()
            }
            if (response['secret']) {
                panel_primary.innerText = response['secret']
            }
            const twofa_qrcode = document.getElementById('2fa-qrcode')
            if (!twofa_qrcode.firstChild) {
                twofa_qrcode.appendChild(svgNode);
            }
            document.getElementById('getTokenButton').style.display = 'none';
            document.getElementById('2fa-user-code').style.display = 'block';

        })
        .catch(error => {
            errorDiv();
        });
}
