const register_button = document.getElementById('register-button');
register_button.addEventListener('click', () => {
    add_key()
})

async function add_key() {
    register().catch(e => alert(e))
}


async function register() {
    const response = await register_begin()
    const registration_status = await register_complete(response.response)
    const credential_id = get_credential_id(response.response)
    if (registration_status) {
        window.location = `/webauthn/keys/name/${credential_id}`
    }
    else {
        window.location = '/webauthn/keys/add'
    }
}

function get_credential_id(resp) {
    const attObj = resp.attestationObject;
    const auth_data = CBOR.decode(attObj).authData;
    const data_uint8array = new Uint8Array(auth_data);
    const data_array = Array.from(data_uint8array);
    const sliced = data_array.slice(55, 55 + 64);
    let result = '';
    for (const c of sliced) {
        result += c.toString(16).padStart(2, '0');
    }
    return result

}
async function register_begin() {
    return await fetch('/webauthn/register/begin', {
        method: 'POST',
    }).then(function (response) {
        if (response.ok) return response.arrayBuffer();
        throw new Error('Error getting registration data!');
    }).then(CBOR.decode).then(function (options) {
        return navigator.credentials.create(options);
    })
}


async function register_complete(resp) {
    return fetch('/webauthn/register/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/cbor' },
        body: CBOR.encode({
            "attestationObject": new Uint8Array(resp.attestationObject),
            "clientDataJSON": new Uint8Array(resp.clientDataJSON),
        })
    }
    ).then(function (response) {
        return response.ok;
    }, function (reason) {
        alert(reason);
    });
}