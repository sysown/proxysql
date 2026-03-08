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
BASE_GROUP="${TAP_GROUP%%-g[0-9]*}" # Strip -g1, -g2 etc.

if [ -n "${TAP_GROUP}" ]; then
    if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(cat "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst")
    elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst" ]; then
        INFRAS_TO_CHECK=$(cat "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst")
    fi
fi

if [ -z "${INFRAS_TO_CHECK}" ]; then
    # Fallback mapping if no infras.lst exists
    if [[ "${TAP_GROUP}" == mysql84* ]]; then INFRA_TYPE="infra-mysql84"; fi
    if [[ "${TAP_GROUP}" == mysql57* ]]; then INFRA_TYPE="infra-mysql57"; fi
    if [[ "${TAP_GROUP}" == mariadb10* ]]; then INFRA_TYPE="infra-mariadb10"; fi
    if [[ "${TAP_GROUP}" == pgsql* ]]; then INFRA_TYPE="docker-pgsql16-single"; fi
    
    INFRA_TYPE="${INFRA_TYPE:-${DEFAULT_MYSQL_INFRA:-infra-mysql84}}"
    INFRAS_TO_CHECK="${INFRA_TYPE}"
fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
NETWORK_NAME="${INFRA_ID}_backend"
TEST_CONTAINER="test-runner.${INFRA_ID}"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
PROXY_DATA_DIR_HOST="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
JENKINS_SCRIPTS_DIR="${HOME}/jenkins-build-scripts"
LEGACY_SCRIPTS_PATH="/var/lib/jenkins/scripts"

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
    -v "${JENKINS_SCRIPTS_DIR}:${LEGACY_SCRIPTS_PATH}" \
    -v "${PROXY_DATA_DIR_HOST}:/var/lib/proxysql" \
    -e WORKSPACE="${WORKSPACE}" \
    -e INFRA_ID="${INFRA_ID}" \
    -e INFRA_TYPE="${INFRA_TYPE}" \
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

        mkdir -p ./test-scripts/deps
        [ -n \"${MYSQL_BINLOG_BIN}\" ] && ln -sf \"${MYSQL_BINLOG_BIN}\" /var/lib/jenkins/scripts/test-scripts/deps/mysqlbinlog
        [ -n \"${BINLOG_READER_BIN}\" ] && ln -sf \"${BINLOG_READER_BIN}\" /var/lib/jenkins/scripts/test-scripts/deps/test_binlog_reader-t
        
        # Source the local isolated environment
        source ${SCRIPT_DIR}/env-isolated.bash
        
        # Execute the Python tester
        python3 /var/lib/jenkins/scripts/test-scripts/bin/proxysql-tester.py
    "

# Clean up only the runner container
echo ">>> Cleaning up Test Runner container"
docker rm -f "${TEST_CONTAINER}" >/dev/null 2>&1 || true
