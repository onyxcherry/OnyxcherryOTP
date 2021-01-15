// sample:
// const data = { "420048e3a0d1c0a1170e53e1ed6a3f59c462a9c7ed86f80a669a663671b7e187d3f9312148abdcd951cf1cd1595b4bedd37e789be792fa49c1c3fa5d56e827df": { "last_access": "Mon, 11 Jan 2021 16:00:34 GMT", "name": "MyBlueKey" } }

function check_if_any_keys() {
    const container = document.getElementById('user-keys')
    if (container !== null) {
        return true
    }
    return false
}
async function get_keys_list() {
    return fetch('/webauthn/keys/list').then(response => response.json())
}

async function build_table() {
    if (!check_if_any_keys()) {
        return
    }
    const data = await get_keys_list()

    const container = document.getElementById('user-keys')
    const table = document.createElement('table')
    const header = document.createElement('tr')

    table.setAttribute('class', 'table')
    table.style.color = "white"

    const key_name_header = document.createElement('th')
    key_name_header.innerText = "Key name"
    header.append(key_name_header)
    const credential_id_header = document.createElement('th')
    credential_id_header.innerText = "Credential id"
    header.append(credential_id_header)
    const last_access_header = document.createElement('th')
    last_access_header.innerText = "Last access"
    header.append(last_access_header)
    const action_header = document.createElement('th')
    action_header.innerText = "Action"
    header.append(action_header)
    const status_header = document.createElement('th')
    status_header.innerText = "Status"
    header.append(status_header)

    table.append(header)

    keys = Object.keys(data)

    for (const key of keys) {
        const row = document.createElement('tr')

        const key_name = document.createElement('td')
        key_name.innerText = data[key]['name']
        row.append(key_name)
        const credential_id = document.createElement('td')
        credential_id.innerText = key.slice(0, 12)
        row.append(credential_id)
        const last_access = document.createElement('td')
        last_access.innerText = new Date(data[key]['last_access']).toLocaleString()
        row.append(last_access)
        const possible_action = document.createElement('td')
        const action_button = create_action_button(key)
        possible_action.append(action_button)
        row.append(possible_action)
        const checking_status = document.createElement('td')
        row.append(checking_status)

        table.append(row)
    }

    container.appendChild(table)
}

function create_action_button(cred_id) {
    const h_container = document.createElement('div')
    h_container.setAttribute('class', 'btn-group')

    h_container.innerHTML = `<button class="btn btn-warning btn-sm dropdown-toggle dropdown-toggle-split" type="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false">Action</button>`

    const s_container = document.createElement('div')
    s_container.setAttribute('class', 'dropdown-menu')
    s_container.style.minWidth = '5rem'

    const rename_bt = document.createElement('a')
    rename_bt.innerText = 'rename'
    rename_bt.setAttribute('class', 'dropdown-item')
    rename_bt.setAttribute('href', `/webauthn/keys/name/${cred_id}`)

    const divider = document.createElement('div')
    divider.setAttribute('class', 'dropdown-divider')

    const delete_bt = document.createElement('a')
    delete_bt.innerText = 'delete'
    delete_bt.setAttribute('class', 'dropdown-item')
    delete_bt.setAttribute('href', `/webauthn/keys/delete/${cred_id}`)

    const att_check = document.createElement('a')
    att_check.innerText = 'check attestation'
    att_check.setAttribute('class', 'dropdown-item')
    att_check.style.whiteSpace = 'pre-wrap'
    att_check.addEventListener('click', (e) => update_status(e.target, cred_id))

    s_container.appendChild(rename_bt)
    s_container.appendChild(delete_bt)
    s_container.appendChild(divider)
    s_container.appendChild(att_check)

    h_container.appendChild(s_container)

    return h_container
}
function add_waiting_status(elem) {
    const status = document.createElement('img')
    status.setAttribute('src', '/static/images/spinning_fan.svg')
    status.setAttribute('id', 'att-waiting-resp')
    const row = elem.closest('tr')
    const dest = row.lastChild
    dest.appendChild(status)
}

async function update_status(elem, cred_id) {
    const row = elem.closest('tr')
    const dest = row.lastChild
    if (dest.firstChild !== null) {
        return
    }
    add_waiting_status(elem)

    const resp = await get_att_data(cred_id)

    if (resp.ok) {
        const row = elem.closest('tr')
        const waiting_status = document.getElementById('att-waiting-resp')
        row.lastChild.removeChild(waiting_status)
        const data = await resp.json()
        const final_att_status = document.createElement('div')
        if (data['status'] === "OK") {
            final_att_status.innerText = "✓"
            final_att_status.style.color = "green"
            final_att_status.style.fontSize = '2rem'
        }
        else {
            final_att_status.innerText = "⤬"
            final_att_status.style.transform = "rotate(90deg)"
            final_att_status.style.color = "red"
            final_att_status.style.fontSize = '2rem'
        }
        row.lastChild.appendChild(final_att_status)
    }
}

async function get_att_data(credential_id) {
    return fetch(`/webauthn/verify_attestation/${credential_id}`)
}
build_table()