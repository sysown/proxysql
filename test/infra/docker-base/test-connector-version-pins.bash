#!/usr/bin/env bash
set -euo pipefail

# Portable pin check for CI runners without ripgrep (uses POSIX grep -F/-x/-q).
dockerfile_path="${1:-$(dirname "$0")/Dockerfile}"

if [ ! -f "$dockerfile_path" ]; then
	echo "ERROR: Dockerfile not found: $dockerfile_path" >&2
	exit 1
fi

expected_arg='ARG MYSQL_CONNECTOR_PYTHON_VERSION=9.7.0'
if ! grep -Fqx -- "$expected_arg" "$dockerfile_path"; then
	echo "ERROR: missing Dockerfile argument: $expected_arg" >&2
	exit 1
fi

for package in mysql-connector-python mysqlx-connector-python; do
	expected_pin="${package}==\${MYSQL_CONNECTOR_PYTHON_VERSION}"
	expected_dependency="\"${expected_pin}\" \\"
	if ! grep -Fq -- "$expected_dependency" "$dockerfile_path"; then
		echo "ERROR: missing package pin: $expected_pin" >&2
		exit 1
	fi
done

echo "PASS: MySQLX Connector/Python version pins are present"
