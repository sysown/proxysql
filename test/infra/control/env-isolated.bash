#!/bin/bash
set -e
set -o pipefail

# Isolated Network Overrides for Test Runner
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

# NOTE: TAP_MYSQLHOST/PORT are set later (after infra .env is sourced)
# so that infra-specific overrides like MYSQL_PRIMARY_HOST take effect.
if [ -n "${DEFAULT_MYSQL_INFRA}" ]; then
    export TAP_MYSQLUSERNAME="root"
    export TAP_MYSQLPASSWORD="${ROOT_PASSWORD}"
fi

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

if [ -n "${DEFAULT_PGSQL_INFRA}" ]; then
    export TAP_PGSQLSERVER_HOST="pgsql1.${DEFAULT_PGSQL_INFRA}"
    export TAP_PGSQLSERVER_PORT=5432
    export TAP_PGSQLSERVER_USERNAME="postgres"
    export TAP_PGSQLSERVER_PASSWORD="${ROOT_PASSWORD}"
fi

export DOCKER_MODE="compose-dns"
export PROXY_CONTAINER="proxysql.${INFRA_ID}"
export REGULAR_INFRA_DATADIR="/var/lib/proxysql"
export TESTS_LOGS_PATH="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/tests"

# Test directories and paths
export TAP_WORKDIR="${WORKSPACE}/test/tap/tests/"
export TAP_WORKDIRS="${WORKSPACE}/test/tap/tests/ ${WORKSPACE}/test/tap/tests_with_deps/deprecate_eof_support/ ${WORKSPACE}/test/tap/tests/unit/"
export TAP_DEPS="${WORKSPACE}/test/tap/tap"
export TAP_DEPS_PATH="${WORKSPACE}/test/tap/tap"
export TEST_DEPS_PATH="${WORKSPACE}/test-scripts/deps"
export TEST_DEPS="${TEST_DEPS_PATH}"

# Cluster Nodes — primary (6032) + nodes inside the ProxySQL container
# Port scheme: primary=6032, proxy-node1=6042, proxy-node2=6052, ..., proxy-node9=6122
# From the test-runner container, reach them via the proxysql hostname
# NOTE: primary MUST be first — test_cluster1-t expects conns[0] to be the primary
NUM_CLUSTER_NODES=${PROXYSQL_CLUSTER_NODES:-9}
if [[ "${SKIP_CLUSTER_START}" == "1" ]] || [[ "${SKIP_CLUSTER_START}" == "true" ]]; then
    NUM_CLUSTER_NODES=0
fi
CLUSTER_NODES=""
if [ "${NUM_CLUSTER_NODES}" -gt 0 ]; then
    CLUSTER_NODES="proxysql:6032,"
    for i in $(seq 1 ${NUM_CLUSTER_NODES}); do
        PORT=$((6032 + i * 10))
        CLUSTER_NODES="${CLUSTER_NODES}proxysql:${PORT},"
    done
fi
export TAP_CLUSTER_NODES=${CLUSTER_NODES%,}

# Build and runtime essentials
export VERS=$(git -C ${WORKSPACE} describe --tags --abbrev=7 2>/dev/null || echo "unknown")
export DIST="ubuntu22-dbg"
export MALLOC_CONF="retain:false"
export PROXYSQL_LAYOUT="flat"

# Test execution defaults
export WITHGCOV="${WITHGCOV:-0}"
export WITHASAN="${WITHASAN:-0}"
export TEST_EXIT_ON_FAIL="${TEST_EXIT_ON_FAIL:-0}"
export TEST_JDBC="${TEST_JDBC:-1}"
export TEST_JDBC_EXIT_ON_FAIL="${TEST_JDBC_EXIT_ON_FAIL:-0}"
export TEST_PY="${TEST_PY:-1}"
export TEST_PY_EXIT_ON_FAIL_SECTION="${TEST_PY_EXIT_ON_FAIL_SECTION:-0}"
export TEST_PY_EXIT_ON_FAIL_TEST="${TEST_PY_EXIT_ON_FAIL_TEST:-0}"
export TEST_PY_INTERNAL="${TEST_PY_INTERNAL:-0}"
export TEST_PY_BENCHMARK="${TEST_PY_BENCHMARK:-0}"
export TEST_PY_CHUSER="${TEST_PY_CHUSER:-0}"
export TEST_PY_STATS="${TEST_PY_STATS:-0}"
export TEST_PY_TAP="${TEST_PY_TAP:-1}"
export TEST_PY_TAPINT="${TEST_PY_TAPINT:-0}"
export TEST_PY_FAILOVER="${TEST_PY_FAILOVER:-0}"
export TEST_PY_WARMING="${TEST_PY_WARMING:-0}"
export TEST_PY_READONLY="${TEST_PY_READONLY:-0}"
export TEST_PY_TAP_REPEAT="${TEST_PY_TAP_REPEAT:-1}"
export TEST_PY_TAP_SHUFFLE_LIMIT="${TEST_PY_TAP_SHUFFLE_LIMIT:-0}"
export TEST_PY_TAP_DUMP_RUNTIME="${TEST_PY_TAP_DUMP_RUNTIME:-1}"
export TEST_PY_TAP_DUMP_STATS="${TEST_PY_TAP_DUMP_STATS:-1}"
# Per-test wall-clock budget, in seconds. 0 disables it entirely, which was
# the previous default: a hung TAP test then ran until the CI job itself was
# killed. 1800 is ~2.4x the slowest single test measured across 47 groups
# (reg_test_3765_ssl_pollout-t, 12.5 min; then test_cluster_sync-t 10.5,
# set_testing-240-t 7.8, test_auth_methods-t 7.7 -- only 4 tests exceed 5
# minutes at all), so it cannot fire on a merely slow test while still
# catching a hang long before the 90-minute step budget.
export TEST_TAP_TIMEOUT="${TEST_TAP_TIMEOUT:-1800}"

# Cluster sync test support — expose first cluster node admin port for replica validation
if [ "${NUM_CLUSTER_NODES}" -gt 0 ]; then
    export TAP_PGSQL_SYNC_REPLICA_PORT="${TAP_PGSQL_SYNC_REPLICA_PORT:-6042}"
fi

# Noise injection for race condition testing
# When enabled, tests that support noise injection will introduce random delays
# and stress to help detect race conditions and deadlocks
# See test/tap/NOISE_TESTING.md for more details
export TAP_USE_NOISE="${TAP_USE_NOISE:-0}"

# TAP test filtering
export TEST_PY_TAP_INCL="${TEST_PY_TAP_INCL:-}"
export TEST_PY_TAP_EXCL="${TEST_PY_TAP_EXCL:-reg_test_3273_ssl_con-t}"
export TEST_PY_TAPINT_INCL="${TEST_PY_TAPINT_INCL:-}"
export TEST_PY_TAPINT_EXCL="${TEST_PY_TAPINT_EXCL:-}"

# Source infra-specific environments (exports WHG, RHG, MYSQL_PRIMARY_HOST, etc.)
# INFRA_TYPE is set by binlog/special groups; DEFAULT_MYSQL_INFRA by all MySQL groups
for _infra_env in "${INFRA_TYPE}" "${DEFAULT_MYSQL_INFRA}"; do
    if [ -n "${_infra_env}" ] && [ -f "${WORKSPACE}/test/infra/${_infra_env}/.env" ]; then
        source "${WORKSPACE}/test/infra/${_infra_env}/.env"
    fi
done
unset _infra_env

# Set TAP_MYSQLHOST/PORT after sourcing infra .env so that MYSQL_PRIMARY_HOST/PORT
# overrides take effect (e.g. dbdeployer uses "dbdeployer1" instead of "mysql1")
if [ -n "${DEFAULT_MYSQL_INFRA}" ]; then
    export TAP_MYSQLHOST="${MYSQL_PRIMARY_HOST:-mysql1}.${DEFAULT_MYSQL_INFRA}"
    export TAP_MYSQLPORT="${MYSQL_PRIMARY_PORT:-3306}"
fi

echo ">>> Isolated Environment Loaded (INFRA_ID: ${INFRA_ID})"
if [ "${TAP_USE_NOISE}" = "1" ] || [ "${TAP_USE_NOISE}" = "true" ]; then
    echo ">>> Noise Injection ENABLED - tests will introduce random delays for race condition testing"
fi
