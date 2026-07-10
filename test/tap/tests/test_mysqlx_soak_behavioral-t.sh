#!/usr/bin/env bash
#
# test_mysqlx_soak_behavioral-t — TAP wrapper for the
# behavioral_validation.py harness (issues #5677, #5678).
#
# Runs inside the test-runner container of the docker-isolated TAP
# harness. Expects the proxysql.${INFRA_ID} container to be up with
# the mysqlx plugin loaded (via the mysqlx-soak group's setup-infras
# hook) and a route 'r1' bound to port 6603, plus a user 'alice' with
# password 'alicepass' provisioned.
#
# This wrapper emits exactly two TAP assertions:
#   1. the PROXYSQL SHUTDOWN SLOW scenario is skipped in the shared
#      proxysql-tester.py runner because that runner writes LOGENTRY and
#      continues with later tests through the same ProxySQL admin port.
#   2. the LOAD MYSQLX ROUTES TO RUNTIME mid-traffic scenario
# Each assertion is "ok" if behavioral_validation.py exited 0 for that
# scenario. The Python script's own internal asserts produce
# diagnostic # comments visible in the TAP output.

set -u
# pipefail so the python3 ... | sed pipeline below propagates the
# Python exit code rather than always returning the (always 0) sed
# exit. Without it a missing harness file or a Python exception
# silently produces ok TAP output.
set -o pipefail

# Walk up from THIS SCRIPT'S directory (not $PWD), which the test
# runner sets to /var/lib/proxysql inside the test-runner container.
# $0 is mounted from the host worktree at its real path, so its
# parent chain reaches src/proxysql_global.cpp regardless of $PWD.
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
HARNESS="${PROXYSQL_PATH}/test/scripts/mysqlx/behavioral_validation.py"

# Connection parameters: inside the test-runner container, the
# ProxySQL container is reachable as 'proxysql' on the docker network;
# admin port 6032, mysqlx port 6603 (per group env.sh).
PROXYSQL_HOST="${MYSQLX_TEST_PROXYSQL_HOST:-proxysql}"
PROXYSQL_PORT="${MYSQLX_TEST_PROXYSQL_PORT:-6603}"
ADMIN_HOST="${MYSQLX_TEST_ADMIN_HOST:-proxysql}"
ADMIN_PORT="${MYSQLX_TEST_ADMIN_PORT:-6032}"
ADMIN_USER="${MYSQLX_TEST_ADMIN_USER:-${TAP_ADMINUSERNAME:-admin}}"
ADMIN_PASS="${MYSQLX_TEST_ADMIN_PASS:-${TAP_ADMINPASSWORD:-admin}}"
TEST_USER="${MYSQLX_TEST_USER:-alice}"
TEST_PASS="${MYSQLX_TEST_PASS:-alicepass}"
PROXY_CONTAINER="proxysql.${INFRA_ID:-dev-$USER}"
ROUTE_NAME="${MYSQLX_ROUTE_NAME:-r1}"
ROUTE_BIND="${MYSQLX_ROUTE_BIND:-0.0.0.0:${PROXYSQL_PORT}}"
ROUTE_HG="${MYSQLX_ROUTE_HG:-10}"

echo "1..2"

# Scenario 1: PROXYSQL SHUTDOWN SLOW mid-traffic
shutdown_scenario() {
    echo "ok 1 - PROXYSQL SHUTDOWN SLOW mid-traffic skipped # SKIP shared proxysql-tester.py needs ProxySQL admin alive after each TAP test"
    return 0
}

restore_route() {
    local out
    out=$(mysql -u"${ADMIN_USER}" -p"${ADMIN_PASS}" -h"${ADMIN_HOST}" -P"${ADMIN_PORT}" 2>&1 >/dev/null <<SQL
DELETE FROM mysqlx_routes WHERE name='${ROUTE_NAME}';
INSERT INTO mysqlx_routes (name, bind, destination_hostgroup, fallback_hostgroup, strategy, active)
    VALUES ('${ROUTE_NAME}', '${ROUTE_BIND}', ${ROUTE_HG}, -1, 'first_available', 1);
LOAD MYSQLX ROUTES TO RUNTIME;
SAVE MYSQLX ROUTES TO DISK;
SQL
)
    local rc=$?
    if [ -n "${out}" ]; then
        printf '%s\n' "${out}" | sed 's/^/# cleanup: /'
    fi
    return "${rc}"
}

# Scenario 2: LOAD MYSQLX ROUTES TO RUNTIME mid-traffic
reload_scenario() {
    # The proxysql container must still be up: this wrapper skips the
    # destructive shutdown scenario above, so an admin probe failure is
    # a real test/setup failure, not a valid skip. Probe the same
    # cross-container admin endpoint that behavioral_validation.py will
    # use; docker exec from inside the test-runner is not portable.
    if ! mysql -u"${ADMIN_USER}" -p"${ADMIN_PASS}" -h"${ADMIN_HOST}" -P"${ADMIN_PORT}" -e 'SELECT 1' >/dev/null 2>&1; then
        echo "# reload scenario admin probe failed using ${ADMIN_USER}@${ADMIN_HOST}:${ADMIN_PORT}"
        return 1
    fi

    python3 -u "${HARNESS}" \
        --proxysql-host "${PROXYSQL_HOST}" --proxysql-port "${PROXYSQL_PORT}" \
        --admin-host "${ADMIN_HOST}" --admin-port "${ADMIN_PORT}" \
        --admin-user "${ADMIN_USER}" --admin-pass "${ADMIN_PASS}" \
        --user "${TEST_USER}" --password "${TEST_PASS}" \
        --clients 5 --scenario reload \
        --route-name "${ROUTE_NAME}" \
        2>&1 | sed 's/^/# /'
    rc=$?

    if restore_route; then
        echo "# cleanup: restored route '${ROUTE_NAME}' on '${ROUTE_BIND}'"
    else
        echo "# cleanup: failed to restore route '${ROUTE_NAME}' on '${ROUTE_BIND}'"
        rc=1
    fi

    if [ "${rc}" -eq 0 ]; then
        echo "ok 2 - LOAD MYSQLX ROUTES TO RUNTIME: in-flight sessions survived, new connection refused"
        return 0
    else
        echo "not ok 2 - LOAD MYSQLX ROUTES TO RUNTIME mid-traffic failed"
        return 1
    fi
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "not ok 1 - python3 not available in test-runner image"
    echo "not ok 2 - python3 not available in test-runner image"
    exit 1
fi
if ! python3 -c 'import mysqlx' 2>/dev/null; then
    echo "not ok 1 - mysql-connector-python (mysqlx) not installed; install via Dockerfile"
    echo "not ok 2 - mysql-connector-python (mysqlx) not installed; install via Dockerfile"
    exit 1
fi

RC=0
shutdown_scenario || RC=1
reload_scenario  || RC=1
exit $RC
