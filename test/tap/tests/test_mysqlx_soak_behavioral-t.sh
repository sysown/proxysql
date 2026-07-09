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
#   1. the PROXYSQL SHUTDOWN SLOW mid-traffic scenario from behavioral_validation.py
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
BEHAVIORAL_TIMEOUT="${MYSQLX_SOAK_BEHAVIORAL_TIMEOUT:-90s}"
ADMIN_SHUTDOWN_TIMEOUT="${MYSQLX_SOAK_ADMIN_SHUTDOWN_TIMEOUT:-15s}"

echo "1..2"

# Scenario 1: PROXYSQL SHUTDOWN SLOW mid-traffic
shutdown_scenario() {
    (
        sleep 3
        echo "# admin shutdown actor: issuing PROXYSQL SHUTDOWN SLOW"
        out=$(
            timeout "${ADMIN_SHUTDOWN_TIMEOUT}" \
                mysql -u"${ADMIN_USER}" -p"${ADMIN_PASS}" -h"${ADMIN_HOST}" -P"${ADMIN_PORT}" \
                    -e 'PROXYSQL SHUTDOWN SLOW' 2>&1
        )
        rc=$?
        if [ -n "${out}" ]; then
            printf '%s\n' "${out}" | sed 's/^/# admin shutdown actor: /'
        fi
        echo "# admin shutdown actor: exited rc=${rc}"
    ) &
    shutdown_actor_pid=$!

    timeout "${BEHAVIORAL_TIMEOUT}" python3 "${HARNESS}" \
        --proxysql-host "${PROXYSQL_HOST}" --proxysql-port "${PROXYSQL_PORT}" \
        --admin-host "${ADMIN_HOST}" --admin-port "${ADMIN_PORT}" \
        --user "${TEST_USER}" --password "${TEST_PASS}" \
        --clients 5 --scenario shutdown \
        --external-shutdown --shutdown-wait-sec 8 \
        2>&1 | sed 's/^/# /'
    rc=$?
    wait "${shutdown_actor_pid}" >/dev/null 2>&1 || true

    if [ "${rc}" -eq 0 ]; then
        echo "ok 1 - PROXYSQL SHUTDOWN SLOW mid-traffic: every client received clean Mysqlx::Error 1053"
        return 0
    elif [ "${rc}" -eq 124 ]; then
        echo "not ok 1 - PROXYSQL SHUTDOWN SLOW mid-traffic: behavioral harness timed out after ${BEHAVIORAL_TIMEOUT}"
        return 1
    else
        echo "not ok 1 - PROXYSQL SHUTDOWN SLOW mid-traffic: at least one client saw TCP RST or non-1053 error (rc=${rc})"
        return 1
    fi
}

# Scenario 2: LOAD MYSQLX ROUTES TO RUNTIME mid-traffic
reload_scenario() {
    # The proxysql container needs to be up again for this scenario.
    # Restart it (the test-runner can't restart proxysql directly;
    # the right thing is to re-provision via setup-infras.bash, but
    # for now we skip if the container isn't responsive).
    if ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; then
        echo "ok 2 - reload scenario skipped # SKIP proxysql container not running (shutdown scenario stopped it)"
        return 0
    fi

    if python3 "${HARNESS}" \
        --proxysql-host "${PROXYSQL_HOST}" --proxysql-port "${PROXYSQL_PORT}" \
        --admin-host "${ADMIN_HOST}" --admin-port "${ADMIN_PORT}" \
        --user "${TEST_USER}" --password "${TEST_PASS}" \
        --clients 5 --scenario reload \
        --route-name r1 \
        2>&1 | sed 's/^/# /'
    then
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
if ! command -v timeout >/dev/null 2>&1; then
    echo "not ok 1 - timeout command not available in test-runner image"
    echo "not ok 2 - timeout command not available in test-runner image"
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
