#!/bin/bash -e

# MySQL 8.4 auto-generates SSL certificates during initialization.
# mysql_ssl_rsa_setup was removed in 8.4 — this script just prints the certs for debugging.

echo "======= MYSQL CLIENT KEY ========"
cat /var/lib/mysql/client-key.pem 2>/dev/null || echo "(not yet generated)"

echo "======= MYSQL CLIENT CERT ========"
cat /var/lib/mysql/client-cert.pem 2>/dev/null || echo "(not yet generated)"

echo "======= MYSQL CA ========"
cat /var/lib/mysql/ca.pem 2>/dev/null || echo "(not yet generated)"
