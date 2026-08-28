#!/bin/bash

# 1. Load standard ProxySQL CI defaults
if [ -f "./env.sh" ]; then
    source ./env.sh
fi

# 2. Apply Isolated Network Overrides
# We use ! -v check to only set them if not already set, 
# OR we force them if we know they must be a specific value for Docker.

export TAP_HOST="proxysql"
export TAP_PORT=6033
export TAP_USERNAME="testuser"
export TAP_PASSWORD="testuser"

export TAP_ROOTHOST="proxysql"
export TAP_ROOTPORT=6033
export TAP_ROOTUSERNAME="root"
export TAP_ROOTPASSWORD="${ROOT_PASSWORD}"

export TAP_ADMINHOST="proxysql"
export TAP_ADMINPORT=6032
export TAP_ADMINUSERNAME="radmin"
export TAP_ADMINPASSWORD="radmin"

# Infrastructure Defaults
# If INFRA_TYPE is set (legacy wrapper), we use it for both.
# Otherwise, we use independent defaults for MySQL and PostgreSQL.
export DEFAULT_MYSQL_INFRA="${INFRA_TYPE:-${DEFAULT_MYSQL_INFRA:-infra-mysql84}}"
export DEFAULT_PGSQL_INFRA="${INFRA_TYPE:-${DEFAULT_PGSQL_INFRA:-docker-pgsql16-single}}"

# MySQL/MariaDB Environment Variables
# MYSQL_PRIMARY_HOST/PORT can be set in the infra's .env to override defaults
# (e.g. dbdeployer uses "dbdeployer1" instead of "mysql1")
export TAP_MYSQLHOST="${MYSQL_PRIMARY_HOST:-mysql1}.${DEFAULT_MYSQL_INFRA}"
export TAP_MYSQLPORT="${MYSQL_PRIMARY_PORT:-3306}"
export TAP_MYSQLUSERNAME="root"
export TAP_MYSQLPASSWORD="${ROOT_PASSWORD}"

# PostgreSQL Environment Variables
export TAP_PGSQL_HOST="proxysql"
export TAP_PGSQL_PORT=6133
export TAP_PGSQL_USERNAME="testuser"
export TAP_PGSQL_PASSWORD="testuser"

export TAP_PGSQLROOT_HOST="proxysql"
export TAP_PGSQLROOT_PORT=6133
export TAP_PGSQLROOT_USERNAME="postgres"
export TAP_PGSQLROOT_PASSWORD="${ROOT_PASSWORD}"

export TAP_PGSQLADMIN_HOST="proxysql"
export TAP_PGSQLADMIN_PORT=6132

export TAP_PGSQLSERVER_HOST="pgsql1.${DEFAULT_PGSQL_INFRA}"
export TAP_PGSQLSERVER_PORT=5432
export TAP_PGSQLSERVER_USERNAME="postgres"
export TAP_PGSQLSERVER_PASSWORD="${ROOT_PASSWORD}"

# Enable DNS mode for tests that check DOCKER_MODE
export DOCKER_MODE="compose-dns"

# Force data directory to the mounted volume
export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
# Ensure tests logs go to the unique INFRA_ID folder
export TESTS_LOGS_PATH="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/tests"
# Ensure tests can find their relative files in the shared workspace
export TAP_WORKDIR="${WORKSPACE}/test/tap/tests/"

# Cluster Nodes
CLUSTER_NODES=""
for i in $(seq 1 9); do
    CLUSTER_NODES="${CLUSTER_NODES}proxy-node${i}:6032,"
done
export TAP_CLUSTER_NODES=${CLUSTER_NODES%,}

# Disable some components for isolated stability
export TEST_PY_INTERNAL=0
export TEST_PY_BENCHMARK=0
export TEST_PY_CHUSER=0
export TEST_PY_STATS=0
export TEST_PY_FAILOVER=0
export TEST_PY_TAP=1

# Hostgroup configuration for isolated environment
# The isolated environment uses hostgroup 1300 for MySQL servers
export TAP_REG_TEST_3549_AUTOCOMMIT_TRACKING___MYSQL_SERVER_HOSTGROUP=1300

echo ">>> Isolated Environment Loaded (INFRA_ID: ${INFRA_ID}, MODE: ${DOCKER_MODE})"
echo ">>> Targets: MySQL (${DEFAULT_MYSQL_INFRA}), PGSQL (${DEFAULT_PGSQL_INFRA})"
