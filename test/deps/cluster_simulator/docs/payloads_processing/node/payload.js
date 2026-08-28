const fs = require('fs');

if (process.argv[2]) {
    file = process.argv[2];
} else {
    console.log('No file for processing supplied.');
    return -1;
}

fs.readFile(file, 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }

    payloads = JSON.parse(data);

    for (let payload of payloads) {
        console.log(payload.__comment__)
        console.log(payload.readonly_servers_init_state)
    }
});
