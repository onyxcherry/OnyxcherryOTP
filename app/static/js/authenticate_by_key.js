const authenticate_button = document.getElementById('authenticate-button');
authenticate_button.addEventListener('click', () => {
    authenticate();
});

if (document.readyState !== "loading") {
    authenticate(); 
} else {
    document.addEventListener("DOMContentLoaded", authenticate);
}

function authenticate() {
    fetch('/webauthn/authenticate/begin', {
        method: 'POST',
    }).then(function (response) {
        if (response.ok) {
            return response.arrayBuffer()
        };
        throw new Error('No credential available to authenticate!');
    }).then(CBOR.decode).then(function (options) {
        return navigator.credentials.get(options);
    }).then(function (assertion) {
        return fetch('/webauthn/authenticate/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/cbor' },
            body: CBOR.encode({
                "credentialId": new Uint8Array(assertion.rawId),
                "authenticatorData": new Uint8Array(assertion.response.authenticatorData),
                "clientDataJSON": new Uint8Array(assertion.response.clientDataJSON),
                "signature": new Uint8Array(assertion.response.signature)
            })
        })
    }).then(function (response) {
        var stat = response.ok ? 'successful' : 'unsuccessful';
        alert('Authentication ' + stat + ' More details in server log...');

        window.location = '/';

    }, function (reason) {
        alert(reason);
        window.location = '/auth/available_options';
    })
}