#!/bin/bash
set -e
set -o pipefail

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

if [ -z "${TAP_GROUP}" ]; then
    echo "ERROR: TAP_GROUP is not set."
    exit 1
fi

# 1. Determine Base Group (strip subgroup suffix)
BASE_GROUP="${TAP_GROUP%%-g[0-9]*}"
LST_PATH=""

if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst" ]; then
    LST_PATH="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/infras.lst"
elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst" ]; then
    LST_PATH="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/infras.lst"
fi

INFRAS=""
if [ -n "${LST_PATH}" ]; then
    INFRAS=$(cat "${LST_PATH}")
    echo ">>> Found infrastructure requirements for group '${TAP_GROUP}' in '${LST_PATH}'"
else
    echo ">>> No infras.lst found for group '${TAP_GROUP}' or '${BASE_GROUP}'."
    [ -n "${INFRA_TYPE}" ] && INFRAS="${INFRA_TYPE}"
fi

# 2. Ensure ProxySQL Control Plane is running first
PROXY_CONTAINER="proxysql.${INFRA_ID}"
echo ">>> Checking if ProxySQL (${PROXY_CONTAINER}) is running..."
if ! docker ps --format '{{.Names}}' | grep -q "^${PROXY_CONTAINER}$"; then
    echo ">>> ProxySQL is NOT running. Starting it now..."
    "${SCRIPT_DIR}/start-proxysql-isolated.bash"
else
    echo ">>> ProxySQL is already running."
fi

# 3. Ensure Docker Compose helper is available
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then COMPOSE_CMD="docker-compose"; fi

# 4. Start Required Backends
for INFRA_NAME in ${INFRAS}; do
    INFRA_DIR="${WORKSPACE}/test/infra/${INFRA_NAME}"
    if [ ! -d "${INFRA_DIR}" ]; then
        echo "ERROR: Infrastructure directory '${INFRA_DIR}' not found!"
        exit 1
    fi

    COMPOSE_PROJECT="${INFRA_NAME}-${INFRA_ID}"
    echo ">>> Checking if backend '${INFRA_NAME}' (Project: ${COMPOSE_PROJECT}) is running..."
    
    # Check if ANY container for this project is running
    if [ -z "$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps -q 2>/dev/null)" ]; then
        echo ">>> '${INFRA_NAME}' is NOT running. Starting it now..."
        cd "${INFRA_DIR}"
        ./docker-compose-init.bash
        cd - >/dev/null
        echo ">>> '${INFRA_NAME}' started successfully."
    else
        echo ">>> '${INFRA_NAME}' is already running."
    fi
done

echo ">>> All required infrastructures for '${TAP_GROUP}' are READY (INFRA_ID: ${INFRA_ID})."
