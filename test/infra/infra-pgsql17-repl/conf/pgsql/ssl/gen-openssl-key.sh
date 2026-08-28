#!/bin/bash

# Generate self-signed SSL certificates for PostgreSQL
# Run this script from the infra-pgsql17-repl directory

cd $(dirname $0)

openssl req -new -text -passout pass:abcd -subj /CN=localhost -out server.req -keyout privkey.pem
openssl rsa -in privkey.pem -passin pass:abcd -out server.key
openssl req -x509 -in server.req -text -key server.key -out server.crt
chmod 600 server.key
chmod 644 server.crt

# Set owner:group to container root:postgres (999 is postgres group ID)
chown 0:999 server.key server.crt

echo "SSL certificates generated successfully."
