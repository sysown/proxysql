#!/bin/bash
set -e
set -o pipefail

DATADIR="${1:-/var/lib/mysql}"
mkdir -p "${DATADIR}"

if [ -f "${DATADIR}/ca.pem" ] && [ -f "${DATADIR}/server-cert.pem" ] && [ -f "${DATADIR}/server-key.pem" ]; then
    exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "${TMPDIR}"' EXIT

openssl genrsa 2048 > "${TMPDIR}/ca-key.pem"
openssl req -new -x509 -nodes -days 3650 -key "${TMPDIR}/ca-key.pem" -subj "/CN=ProxySQL MySQL56 Test CA" > "${TMPDIR}/ca.pem"
openssl req -newkey rsa:2048 -days 3650 -nodes -keyout "${TMPDIR}/server-key.pem" -subj "/CN=mysql1.infra-mysql56-single" > "${TMPDIR}/server-req.pem"
openssl rsa -in "${TMPDIR}/server-key.pem" -out "${TMPDIR}/server-key.pem"
openssl x509 -req -in "${TMPDIR}/server-req.pem" -days 3650 -CA "${TMPDIR}/ca.pem" -CAkey "${TMPDIR}/ca-key.pem" -set_serial 01 > "${TMPDIR}/server-cert.pem"

install -m 0644 "${TMPDIR}/ca.pem" "${DATADIR}/ca.pem"
install -m 0644 "${TMPDIR}/server-cert.pem" "${DATADIR}/server-cert.pem"
install -m 0600 "${TMPDIR}/server-key.pem" "${DATADIR}/server-key.pem"
