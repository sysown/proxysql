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
    echo "Usage: TAP_GROUP=<group_name> ./destroy-infras.bash"
    echo "Example: TAP_GROUP=mysql84-g1 ./destroy-infras.bash"
    exit 1
fi

# 1. Determine Base Group (strip subgroup suffix)
BASE_GROUP=$(echo "${TAP_GROUP}" | sed -E "s/[-_]g[0-9]+.*//")
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
elif [ -n "${INFRA_TYPE}" ]; then
    echo ">>> No infras.lst found. Using fallback INFRA_TYPE: ${INFRA_TYPE}"
    INFRAS="${INFRA_TYPE}"
else
    # Simulator-backed groups legitimately omit both; nothing to tear down besides ProxySQL.
    echo ">>> No infras.lst or INFRA_TYPE for group '${TAP_GROUP}'; only stopping ProxySQL."
fi

# 2. Ensure Docker Compose helper is available
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then COMPOSE_CMD="docker-compose"; fi

# 3. Stop ProxySQL Control Plane
echo ">>> Stopping ProxySQL..."
"${SCRIPT_DIR}/stop-proxysql-isolated.bash" || true

# 4. Destroy Required Backends (in reverse order)
echo ">>> Destroying backends for group '${TAP_GROUP}'..."
for INFRA_NAME in ${INFRAS}; do
    INFRA_DIR="${WORKSPACE}/test/infra/${INFRA_NAME}"
    if [ ! -d "${INFRA_DIR}" ]; then
        echo "WARNING: Infrastructure directory '${INFRA_DIR}' not found, skipping..."
        continue
    fi

    COMPOSE_PROJECT="${INFRA_NAME}-${INFRA_ID}"
    echo ">>> Destroying backend '${INFRA_NAME}' (Project: ${COMPOSE_PROJECT})..."

    if [ -f "${INFRA_DIR}/docker-compose-destroy.bash" ]; then
        cd "${INFRA_DIR}"
        ./docker-compose-destroy.bash || echo "WARNING: Failed to destroy ${INFRA_NAME}"
        cd - >/dev/null
    else
        echo ">>> Using docker compose down for '${INFRA_NAME}'..."
        cd "${INFRA_DIR}"
        $COMPOSE_CMD -p "${COMPOSE_PROJECT}" down -v 2>/dev/null || true
        cd - >/dev/null
    fi
done

echo ">>> Cleanup complete for group '${TAP_GROUP}' (INFRA_ID: ${INFRA_ID})."
echo ">>> To re-initialize, run: TAP_GROUP=${TAP_GROUP} ./ensure-infras.bash"
