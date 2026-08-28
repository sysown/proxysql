#!/bin/bash -e


mysql_ssl_rsa_setup -s $(echo ${HOSTNAME} | sed 's/mysql//' | sed 's/infra//' | tr -d '.-' | head -c 17)

echo "======= MYSQL CLIENT KEY ========"
cat /var/lib/mysql/client-key.pem

echo "======= MYSQL CLIENT CERT ========"
cat /var/lib/mysql/client-cert.pem

echo "======= MYSQL CA ========"
cat /var/lib/mysql/ca.pem
