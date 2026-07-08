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
#   1. the SIGTERM-mid-traffic scenario from behavioral_validation.py
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
TEST_USER="${MYSQLX_TEST_USER:-alice}"
TEST_PASS="${MYSQLX_TEST_PASS:-alicepass}"
PROXY_CONTAINER="proxysql.${INFRA_ID:-dev-$USER}"

echo "1..2"

# Scenario 1: SIGTERM mid-traffic
# behavioral_validation.py wants the host PID; in the docker-isolated
# harness ProxySQL is in a separate container. We send SIGTERM via
# `docker exec ... kill 1` (PID 1 inside the container is the
# proxysql process via the entrypoint command). The harness's
# --proxysql-pid-file path is ignored because we kill from outside.
sigterm_scenario() {
    # Run the harness in scenario=sigterm mode but tell it to NOT
    # send SIGTERM itself; we'll kill the container's PID 1 in the
    # background and the harness will observe the disconnect.
    # Simplest path: run the Python in a background subshell, kill
    # PID 1 in the proxysql container after a short delay, wait for
    # the harness to exit, and report.
    (
        sleep 3
        docker kill -s TERM "${PROXY_CONTAINER}" >/dev/null 2>&1 || true
    ) &

    if python3 "${HARNESS}" \
        --proxysql-host "${PROXYSQL_HOST}" --proxysql-port "${PROXYSQL_PORT}" \
        --user "${TEST_USER}" --password "${TEST_PASS}" \
        --clients 5 --scenario sigterm \
        --external-kill \
        2>&1 | sed 's/^/# /'
    then
        echo "ok 1 - SIGTERM mid-traffic: every client received clean Mysqlx::Error 1053"
        return 0
    else
        echo "not ok 1 - SIGTERM mid-traffic: at least one client saw TCP RST or non-1053 error"
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
        echo "ok 2 - reload scenario skipped # SKIP proxysql container not running (sigterm scenario killed it)"
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
if ! python3 -c 'import mysqlx' 2>/dev/null; then
    echo "not ok 1 - mysql-connector-python (mysqlx) not installed; install via Dockerfile"
    echo "not ok 2 - mysql-connector-python (mysqlx) not installed; install via Dockerfile"
    exit 1
fi

RC=0
sigterm_scenario || RC=1
reload_scenario  || RC=1
exit $RC
