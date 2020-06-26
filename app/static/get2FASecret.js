const userLang = window.navigator.language
const pl = ['pl', 'pl-PL']

const panel_info = document.querySelector('.panel-info')
const panel_danger = document.querySelector('.panel-danger')
const panel_success = document.querySelector('.panel-success')
const panel_primary = document.querySelector('.panel-primary')

function invalidCode() {
    panel_danger.firstElementChild.innerText = "Błędny kod OTP!"
    panel_danger.children[1].innerText = "Spróbuj ponownie."
    panel_danger.style.display = "block";
};

function changeSecretView() {
    if (document.getElementById('2fa-qrcode').style.display == 'block') {
        document.getElementById('2fa-qrcode').style.display = 'none';
        panel_primary.style.display = "block";
        document.getElementById('changeview').innerText = "Show QR Code"
        panel_info.style.display = "none"
    } else {
        document.getElementById('2fa-qrcode').style.display = 'block';
        panel_primary.style.display = "none";
        document.getElementById('changeview').innerText = "Show secret as text"
        panel_info.style.display = "block"
    }
}


function submitForm(e, form) {
    e.preventDefault();
    fetch('http://127.0.0.1:5777/auth/checkcode', {
        method: 'post',
        headers: {
            "Content-Type": "text/plain"
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
            panel_success.style.display = "block"
            panel_info.style.display = "none";
            panel_danger.style.display = "none"
            panel_success.firstElementChild.innerText = "Turned on OTP."
            panel_success.children[1].innerText = "You could go to the main page."
        }
    }).catch(function(err) {
        alert('Error')
    });
}

function errorDiv() {

    panel_danger.style.display = "block";
    if (pl.includes(userLang)) {
        panel_danger.firstElementChild.innerText = "Wystąpił błąd."
        panel_danger.children[1].innerText = "Skontaktuj się z administratorem serwisu."

    } else {
        panel_danger.firstElementChild.innerText = "An error occured."
        panel_danger.children[1].innerText = "Please contact the administrator."
    }
}

function getToken() {
    fetch("http://127.0.0.1:5777/auth/generate_token")
        .then(response => {
            if (response.ok) {
                return response.json()
            } else {
                errorDiv();
                return Promise.reject(response)
            }
        })
        .then(response => {
            panel_info.firstElementChild.innerText = 'Scan the QR and type the code from app below.'
            panel_info.children[1].innerText = 'Use an OTP app, e.g. Authy or Google Authenticator.'
            if (response['for_qrcode']) {
                var svgNode = QRCode(response['for_qrcode'])
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