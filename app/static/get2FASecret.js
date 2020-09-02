const base_url = `${window.location.protocol}//${window.location.hostname}:${window.location.port}`
var already_showed_qrcode = false;
const twofa_messages = document.getElementById('twofa-messages')
const otp_code_form = document.getElementById('otp_code_form')
const twofa_qrcode = document.getElementById('twofa-qrcodeAAA')
const twofa_text_code = document.getElementById('twofa-text-code')
const get_token_button = document.getElementById('get-token-button')
const change_view_buttonAAA = document.getElementById('change-viewAAA')


check_code_form = document.getElementById('otp_code_form')
check_code_form.addEventListener('submit', e => {
    submitForm(e, check_code_form)
})


async function postFormData(url, value) {
    const response = await fetch(url, {
        method: 'post',
        headers: {
            'Content-Type': 'text/plain'
        },
        body: value
    });
    try {
        return response.json()
    }
    catch (error) { return console.log(error) }
}

async function submitForm(e, form) {
    e.preventDefault();
    const data = await postFormData(`${base_url}/twofa/checkcode`, form.otp_code.value);
    const status = data['status']
    const message = data['message']

    twofa_messages.innerText = message
    twofa_messages.style.display = 'block'

    if (status === 'OK') {
        otp_code_form.style.display = 'none'
        change_view_buttonAAA.style.display = 'none'
        get_token_button.style.display = 'none'
        twofa_qrcode.style.display = 'none'
        twofa_text_code.style.display = 'none'
    }
}


async function getJsonData(url) {
    const response = await fetch(url)
    try {
        return response.json()
    }
    catch (error) { return console.log(error) }
}

function change_viewAAAAAAA() {
    if (already_showed_qrcode) {
        showTextCodeAAA();
        already_showed_qrcode = false;
    }
    else {
        showQRCodeAAA();
        already_showed_qrcode = true;
    }
}

change_view_buttonAAA.addEventListener('click', () => {
    change_viewAAAAAAA()
})

get_token_button.addEventListener('click', () => {
    createQRCode()
    change_viewAAAAAAA()
    otp_code_form.style.display = 'block'
    change_view_buttonAAA.style.display = 'block'
    get_token_button.style.display = 'none'
    twofa_messages.style.display = 'none'
})

async function createQRCode() {
    const url = `${base_url}/twofa/generate_token`;
    const data = await getJsonData(url);
    if (data['status'] === 'OK') {
        const secret = data['secret']
        const app_qrcode = data['app_qrcode']
        const svgNode = QRCode({ msg: app_qrcode, pad: 1, pal: ['#000000', '#ffffff'] })
        if (!twofa_qrcode.firstChild) {
            twofa_qrcode.appendChild(svgNode);
        }
        twofa_text_code.innerText = secret
    }
    else { console.log('An error occurred') }


}

function showQRCodeAAA() {
    twofa_qrcode.style.display = 'block'
    twofa_text_code.style.display = 'none'
    change_view_buttonAAA.innerText = 'Show secret as text'
}

function showTextCodeAAA() {
    twofa_qrcode.style.display = 'none'
    twofa_text_code.style.display = 'block'
    change_view_buttonAAA.innerText = 'Show QR Code'

}
