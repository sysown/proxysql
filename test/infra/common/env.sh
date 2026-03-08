#!/bin/bash

# This script sets up the environment variables for TAP tests to connect to
# the containerized ProxySQL and backend servers.

# Get the repository root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"
export WORKSPACE="${REPO_ROOT}"

# Root password is deterministic based on INFRA_ID
export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)

# ProxySQL connection details
export TAP_HOST="proxysql"
export TAP_PORT=6033
export TAP_USERNAME="testuser"
export TAP_PASSWORD="testuser"

export TAP_ROOTHOST="proxysql"
export TAP_ROOTPORT=6033
export TAP_ROOTUSERNAME="root"
export TAP_ROOTPASSWORD="root"

export TAP_ADMINHOST="proxysql"
export TAP_ADMINPORT=6032
export TAP_ADMINUSERNAME="admin"
export TAP_ADMINPASSWORD="admin"

# Backend discovery
# These are the default hostnames inside the ${INFRA_ID}_backend network
export TAP_MYSQLHOST="mysql1.infra-mysql84"
export TAP_MYSQLPORT=3306
export TAP_MYSQLUSERNAME="root"
export TAP_MYSQLPASSWORD="${ROOT_PASSWORD}"

export TAP_PGSQLSERVER_HOST="pgdb1.pgsql16-single"
export TAP_PGSQLSERVER_PORT=5432
export TAP_PGSQLSERVER_USERNAME="postgres"
export TAP_PGSQLSERVER_PASSWORD="${ROOT_PASSWORD}"

export INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
