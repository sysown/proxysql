#!/usr/bin/env bash
#
# test_mysqlx_soak_stress-t — TAP wrapper for stress.py (issue #5681).
#
# Runs a short stress against the chassis-loaded ProxySQL: N
# concurrent X-Protocol clients running steady SELECT loops with
# connection churn, captures throughput / RSS / fd / thread-count
# over time. The harness has its own pass/fail logic (error rate <
# 0.1%); we surface that as a single TAP assertion.
#
# Inside CI the duration is short (default 60s) so the soak fits in a
# CI timeout. For long-running validation (24-72h soak per issue
# #5677), invoke stress.py directly with --duration 24h.

set -u
# pipefail so the python3 ... | sed pipeline below propagates the
# Python exit code rather than always returning the (always 0) sed
# exit. Without it a missing harness file or a Python exception
# silently produces ok TAP output.
set -o pipefail

# Walk up from THIS SCRIPT'S directory (not $PWD, which the test
# runner sets to /var/lib/proxysql inside the test-runner container).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROXYSQL_PATH=$(
    d="$SCRIPT_DIR"
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        if [ -f "$d/src/proxysql_global.cpp" ]; then echo "$d"; exit 0; fi
        if [ "$d" = "/" ]; then break; fi
        d="$(dirname "$d")"
    done
    echo "."
)
HARNESS="${PROXYSQL_PATH}/test/scripts/mysqlx/stress.py"

PROXYSQL_HOST="${MYSQLX_TEST_PROXYSQL_HOST:-proxysql}"
PROXYSQL_PORT="${MYSQLX_TEST_PROXYSQL_PORT:-6603}"
ADMIN_HOST="${MYSQLX_TEST_ADMIN_HOST:-proxysql}"
ADMIN_PORT="${MYSQLX_TEST_ADMIN_PORT:-6032}"
TEST_USER="${MYSQLX_TEST_USER:-alice}"
TEST_PASS="${MYSQLX_TEST_PASS:-alicepass}"

DURATION="${MYSQLX_SOAK_DURATION:-60s}"
CONCURRENT="${MYSQLX_SOAK_CONCURRENT:-20}"
METRICS_OUT="${MYSQLX_SOAK_METRICS_OUT:-/tmp/mysqlx_stress_${INFRA_ID:-local}.csv}"

echo "1..1"

if ! command -v python3 >/dev/null 2>&1; then
    echo "not ok 1 - python3 not available in test-runner image"
    exit 1
fi
if ! python3 -c 'import mysqlx, mysql.connector' 2>/dev/null; then
    echo "not ok 1 - mysql-connector-python (mysqlx + classic) not installed; install via Dockerfile"
    exit 1
fi

if python3 -u "${HARNESS}" \
    --proxysql-host "${PROXYSQL_HOST}" --proxysql-port "${PROXYSQL_PORT}" \
    --admin-host "${ADMIN_HOST}" --admin-port "${ADMIN_PORT}" \
    --admin-user "${TAP_ADMINUSERNAME:-radmin}" \
    --admin-pass "${TAP_ADMINPASSWORD:-radmin}" \
    --user "${TEST_USER}" --password "${TEST_PASS}" \
    --concurrent "${CONCURRENT}" --duration "${DURATION}" \
    --metrics-out "${METRICS_OUT}" \
    2>&1 | sed 's/^/# /'
then
    echo "ok 1 - mysqlx stress (concurrent=${CONCURRENT}, duration=${DURATION}): error rate < 0.1%"
    exit 0
else
    echo "not ok 1 - mysqlx stress (concurrent=${CONCURRENT}, duration=${DURATION}): exceeded error-rate threshold or crashed"
    exit 1
fi
