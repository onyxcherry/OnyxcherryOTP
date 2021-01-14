// sample:
// const data = { "420048e3a0d1c0a1170e53e1ed6a3f59c462a9c7ed86f80a669a663671b7e187d3f9312148abdcd951cf1cd1595b4bedd37e789be792fa49c1c3fa5d56e827df": { "last_access": "Mon, 11 Jan 2021 16:00:34 GMT", "name": "MyBlueKey" } }

async function get_keys_list() {
    return fetch('/webauthn/keys/list').then(response => response.json())
}

async function build_table() {
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
        table.append(row)
    }

    container.appendChild(table)
}
build_table()