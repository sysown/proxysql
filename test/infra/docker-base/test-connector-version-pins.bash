#!/usr/bin/env bash
set -euo pipefail

dockerfile_path="${1:-$(dirname "$0")/Dockerfile}"

expected_arg='ARG MYSQL_CONNECTOR_PYTHON_VERSION=9.7.0'
if ! rg -Fqx -- "$expected_arg" "$dockerfile_path"; then
    echo "ERROR: missing Dockerfile argument: $expected_arg" >&2
    exit 1
fi

for package in mysql-connector-python mysqlx-connector-python; do
    expected_pin="${package}==\${MYSQL_CONNECTOR_PYTHON_VERSION}"
    if ! rg -Fq -- "$expected_pin" "$dockerfile_path"; then
        echo "ERROR: missing package pin: $expected_pin" >&2
        exit 1
    fi
done

echo "PASS: MySQLX Connector/Python version pins are present"
