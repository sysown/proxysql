#!/bin/bash
set -e
set -o pipefail

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"
export INFRA="${INFRA:-${INFRA_TYPE}}"

expand_infra_list() {
    local list_path="$1"
    while IFS= read -r infra_name; do
        [ -n "${infra_name}" ] || continue
        eval "printf '%s\n' \"${infra_name}\""
    done < "${list_path}"
}

if [ -z "${TAP_GROUP}" ]; then
    echo "ERROR: TAP_GROUP is not set."
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
    INFRAS=$(expand_infra_list "${LST_PATH}")
    echo ">>> Found infrastructure requirements for group '${TAP_GROUP}' in '${LST_PATH}'"
else
    if [ -n "${INFRA_TYPE}" ]; then
        echo ">>> No infras.lst found. Using fallback INFRA_TYPE: ${INFRA_TYPE}"
        INFRAS="${INFRA_TYPE}"
    else
        echo "ERROR: Could not find infrastructure requirements (infras.lst) for group '${TAP_GROUP}' or '${BASE_GROUP}'."
        echo "Please ensure test/tap/groups/${BASE_GROUP}/infras.lst exists."
        exit 1
    fi
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
        # Run proxy post-configuration to ensure query rules are loaded
        if [ -f "${INFRA_DIR}/bin/docker-proxy-post.bash" ]; then
            echo ">>> Ensuring ProxySQL configuration for '${INFRA_NAME}'..."
            cd "${INFRA_DIR}"
            ./bin/docker-proxy-post.bash || true
            cd - >/dev/null
        fi
    fi
done

echo ">>> All required infrastructures for '${TAP_GROUP}' are READY (INFRA_ID: ${INFRA_ID})."

# 5. Derive DEFAULT_MYSQL_INFRA and DEFAULT_PGSQL_INFRA for hooks
# These are used by group-specific hooks to connect to backends
for INFRA_NAME in ${INFRAS}; do
    if [[ "${INFRA_NAME}" == *mysql* ]] || [[ "${INFRA_NAME}" == *mariadb* ]]; then
        export DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA:-${INFRA_NAME}}"
    fi
    if [[ "${INFRA_NAME}" == *pgsql* ]] || [[ "${INFRA_NAME}" == *pgdb* ]]; then
        export DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA:-${INFRA_NAME}}"
    fi
done

# 6. Execute group-specific setup hook if it exists
# This allows TAP groups to perform additional setup after all backends are running
SETUP_HOOK="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/setup-infras.bash"
if [ ! -f "${SETUP_HOOK}" ]; then
    # Try base group if subgroup doesn't have the hook
    SETUP_HOOK="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/setup-infras.bash"
fi

if [ -f "${SETUP_HOOK}" ]; then
    echo ">>> Executing group setup hook: ${SETUP_HOOK}"
    "${SETUP_HOOK}"
fi
