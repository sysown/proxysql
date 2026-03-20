#!/bin/bash
set -e
set -o pipefail

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

# 1. Determine Required Infras
INFRAS_TO_CHECK=""
BASE_GROUP=$(echo "${TAP_GROUP}" | sed -E "s/[-_]g[0-9]+.*//") # Strip -g1, -g2, _g1, _g2 etc.

if [ -n "${TAP_GROUP}" ]; then
    if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(cat "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst")
    elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(cat "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst")
    fi
fi

# If no list found, use INFRA_TYPE as single requirement
if [ -z "${INFRAS_TO_CHECK}" ]; then
    INFRAS_TO_CHECK="${INFRA_TYPE}"
fi

# 2. Automatically derive DEFAULT_MYSQL_INFRA and DEFAULT_PGSQL_INFRA
# We take the first compatible infrastructure found in the list.
if [ -n "${INFRAS_TO_CHECK}" ]; then
    for INFRA in ${INFRAS_TO_CHECK}; do
        if [[ "${INFRA}" == *mysql* ]] || [[ "${INFRA}" == *mariadb* ]]; then
            export DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA:-${INFRA}}"
        fi
        if [[ "${INFRA}" == *pgsql* ]] || [[ "${INFRA}" == *pgdb* ]]; then
            export DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA:-${INFRA}}"
        fi
    done
fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
NETWORK_NAME="${INFRA_ID}_backend"
TEST_CONTAINER="test-runner.${INFRA_ID}"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
PROXY_DATA_DIR_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"



# VERIFICATION: Verify ProxySQL is running
PROXY_CONTAINER="proxysql.${INFRA_ID}"
echo ">>> Verifying ProxySQL container: ${PROXY_CONTAINER}"
if ! docker ps --format '{{.Names}}' | grep -q "^${PROXY_CONTAINER}$"; then
    echo "ERROR: ProxySQL container ${PROXY_CONTAINER} is NOT running!"
    exit 1
fi

# VERIFICATION: Verify all required backend containers are running
for INFRA_NAME in ${INFRAS_TO_CHECK}; do
    echo ">>> Verifying Backend: ${INFRA_NAME}"
    # Extract container names from the infra's docker-compose.yml
    if [ -f "${WORKSPACE}/test/infra/${INFRA_NAME}/docker-compose.yml" ]; then
        # Project name used by init script
        COMPOSE_PROJECT="${INFRA_NAME}-${INFRA_ID}"
        # Get all services for this project
        RUNNING_CONTAINERS=$(docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" --format '{{.Names}}')
        if [ -z "${RUNNING_CONTAINERS}" ]; then
            if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then LST_PATH="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst"; else LST_PATH="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst"; fi
            echo "ERROR: Required infrastructure '${INFRA_NAME}' is NOT running."
            if [ -f "${LST_PATH}" ]; then
                echo "According to '${LST_PATH}', this infrastructure is mandatory for the '${TAP_GROUP}' group."
            fi
            echo "Please run initialization for '${INFRA_NAME}' first (e.g. cd test/infra/${INFRA_NAME} && ./docker-compose-init.bash)."
            exit 1
        fi
        echo "Found running containers: ${RUNNING_CONTAINERS//$'\n'/ }"
    else
        echo "ERROR: Infrastructure directory ${INFRA_NAME} not found!"
        exit 1
    fi
done

echo ">>> INFRASTRUCTURE VERIFIED. LAUNCHING TEST RUNNER..."

# Cleanup old test runner if exists
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true

# Prepare logs path
TESTS_LOGS_PATH_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/tests"
mkdir -p "${TESTS_LOGS_PATH_HOST}"
chmod 777 "${TESTS_LOGS_PATH_HOST}"

# Find binaries
MYSQL_BINLOG_BIN=$(find "${WORKSPACE}" -path "${WORKSPACE}/ci_infra_logs" -prune -o -path "${WORKSPACE}/.git" -prune -o -name "mysqlbinlog" -type f -executable -print | head -n 1)
BINLOG_READER_BIN=$(find "${WORKSPACE}" -path "${WORKSPACE}/ci_infra_logs" -prune -o -path "${WORKSPACE}/.git" -prune -o -name "test_binlog_reader-t" -type f -executable -print | head -n 1)

# Execution: run the container
docker run \
    --name "${TEST_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    --cap-add=NET_ADMIN \
    --cap-add=SYS_ADMIN \
    -v "${WORKSPACE}:${WORKSPACE}" \
        -v "${PROXY_DATA_DIR_HOST}:/var/lib/proxysql" \
    -e WORKSPACE="${WORKSPACE}" \
    -e INFRA_ID="${INFRA_ID}" \
    -e INFRA_TYPE="${INFRA_TYPE}" \
    -e DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA}" \
    -e DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA}" \
    -e ROOT_PASSWORD="${ROOT_PASSWORD}" \
    -e TEST_PY_TAP_INCL="${TEST_PY_TAP_INCL}" \
    -e TAP_GROUP="${TAP_GROUP}" \
    -e SKIP_CLUSTER_START="${SKIP_CLUSTER_START}" \
    -e PROXYSQL_CLUSTER_NODES="${PROXYSQL_CLUSTER_NODES}" \
    proxysql-ci-base:latest \
    /bin/bash -c "
        set -e
        git config --global --add safe.directory \"${WORKSPACE}\"
        
        # Redirection: Replace reference to legacy scripts with local infra control scripts
        find \"${WORKSPACE}/test/tap/groups\" -name \"*.bash\" | xargs -r sed -i \"s|\\\$JENKINS_SCRIPTS_PATH|${WORKSPACE}/test/infra/control|g\"

        # Cleanup legacy .env files inside container view
        find \"${WORKSPACE}/test/tap/tests\" -name \".env\" -o -name \"tests.env\" | while read f; do
            sed -i '/TAP_ROOT/d' \"\$f\"
            sed -i '/TAP_MYSQL/d' \"\$f\"
        done

        mkdir -p \"${WORKSPACE}/test-scripts/deps\"
        [ -n \"${MYSQL_BINLOG_BIN}\" ] && ln -sf \"${MYSQL_BINLOG_BIN}\" \"${WORKSPACE}/test-scripts/deps/mysqlbinlog\"
        [ -n \"${BINLOG_READER_BIN}\" ] && ln -sf \"${BINLOG_READER_BIN}\" \"${WORKSPACE}/test-scripts/deps/test_binlog_reader-t\"
        
        # Source the local isolated environment
        source ${SCRIPT_DIR}/env-isolated.bash
        
        # Execute the Python tester
        python3 "${WORKSPACE}/test/scripts/bin/proxysql-tester.py"
    "

# Execute group-specific pre-cleanup hook if it exists
# This runs before the test runner container is removed, allowing cleanup
# of ProxySQL-specific configuration while admin is still accessible
if [ -n "${TAP_GROUP}" ]; then
    PRE_CLEANUP_HOOK="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/pre-cleanup.bash"
    if [ ! -f "${PRE_CLEANUP_HOOK}" ]; then
        PRE_CLEANUP_HOOK="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/pre-cleanup.bash"
    fi

    if [ -f "${PRE_CLEANUP_HOOK}" ]; then
        echo ">>> Executing group pre-cleanup hook: ${PRE_CLEANUP_HOOK}"
        "${PRE_CLEANUP_HOOK}" || true  # Allow cleanup to fail
    fi
fi

# Clean up only the runner container
echo ">>> Cleaning up Test Runner container"
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true
