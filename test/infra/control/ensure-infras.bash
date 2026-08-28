#!/bin/bash
set -e
set -o pipefail

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"
source "${SCRIPT_DIR}/readiness.bash"

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

# Source group env.sh to pick up SKIP_PROXYSQL and other group-level settings
if [ -f "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/env.sh" ]; then
    source "${WORKSPACE}/test/tap/groups/${TAP_GROUP}/env.sh"
elif [ -f "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/env.sh" ]; then
    source "${WORKSPACE}/test/tap/groups/${BASE_GROUP}/env.sh"
fi

# If SKIP_PROXYSQL is set, skip all infrastructure setup
if [ "${SKIP_PROXYSQL}" = "1" ]; then
    echo ">>> SKIP_PROXYSQL=1: Skipping ProxySQL and backend infrastructure for group '${TAP_GROUP}'."
    echo ">>> ensure-infras.bash completed (no infrastructure needed)."
    exit 0
fi

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
elif [ -n "${INFRA_TYPE}" ]; then
    echo ">>> No infras.lst found. Using fallback INFRA_TYPE: ${INFRA_TYPE}"
    INFRAS="${INFRA_TYPE}"
else
    # Simulator-backed TAP groups (e.g. aurora-sim-g1) drive ProxySQL directly
    # through its admin port and do not require any real backend containers,
    # so it is legitimate for them to omit both infras.lst and INFRA_TYPE.
    echo ">>> No infras.lst or INFRA_TYPE for group '${TAP_GROUP}'; continuing with no backend infrastructure."
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

# 3. Execute pre-proxysql hooks — BEFORE starting backends.
# Backends need ProxySQL (and optionally the cluster) to be fully ready
# because their docker-proxy-post.bash configures ProxySQL.
#
# Dispatches both flavors: `.bash` runs host-side; `.sql` is piped into the
# ProxySQL container over the admin port. Per-flavor fallback: TAP_GROUP ->
# BASE_GROUP -> default (default only supplies `.bash`). Both flavors run in
# order so a group can do host-side setup first and admin-var tweaks after.
for EXT in bash sql; do
    HOOK="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/pre-proxysql.${EXT}"
    if [ ! -f "${HOOK}" ]; then
        HOOK="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/pre-proxysql.${EXT}"
    fi
    if [ ! -f "${HOOK}" ] && [ "${EXT}" = "bash" ]; then
        HOOK="${WORKSPACE}/test/tap/groups/default/pre-proxysql.${EXT}"
    fi
    [ -f "${HOOK}" ] || continue

    if [ "${EXT}" = "bash" ]; then
        echo ">>> Executing pre-proxysql hook: ${HOOK}"
        "${HOOK}"
    else
        echo ">>> Applying pre-proxysql admin SQL: ${HOOK}"
        docker exec -i "proxysql.${INFRA_ID}" \
            mysql -uadmin -padmin -h127.0.0.1 -P6032 < "${HOOK}"
    fi
done

PROXYSQL_READY_PORTS=(6032 6033 6132 6133)
if [ -n "${PROXYSQL_READY_PORTS_EXTRA:-}" ]; then
    read -r -a EXTRA_READY_PORTS <<< "${PROXYSQL_READY_PORTS_EXTRA}"
    PROXYSQL_READY_PORTS+=("${EXTRA_READY_PORTS[@]}")
fi
wait_for_proxysql_ports "${PROXY_CONTAINER}" 30 "${PROXYSQL_READY_PORTS[@]}"

# 4. Ensure Docker Compose helper is available
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then COMPOSE_CMD="docker-compose"; fi

# 5. Start Required Backends — one by one, sequentially
# Each backend's docker-compose-init.bash starts containers, waits for
# health, provisions users, and configures ProxySQL via docker-proxy-post.bash.
for INFRA_NAME in ${INFRAS}; do
    INFRA_DIR="${WORKSPACE}/test/infra/${INFRA_NAME}"
    if [ ! -d "${INFRA_DIR}" ]; then
        echo "ERROR: Infrastructure directory '${INFRA_DIR}' not found!"
        exit 1
    fi

    COMPOSE_PROJECT="${INFRA_NAME}-${INFRA_ID}"
    echo ">>> Checking if backend '${INFRA_NAME}' (Project: ${COMPOSE_PROJECT}) is running..."

    if [ -z "$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps -q 2>/dev/null)" ]; then
        echo ">>> '${INFRA_NAME}' is NOT running. Starting it now..."
        cd "${INFRA_DIR}"
        ./docker-compose-init.bash
        cd - >/dev/null
        echo ">>> '${INFRA_NAME}' started successfully."
    else
        echo ">>> '${INFRA_NAME}' is already running."
        if [ -f "${INFRA_DIR}/bin/docker-proxy-post.bash" ]; then
            echo ">>> Ensuring ProxySQL configuration for '${INFRA_NAME}'..."
            cd "${INFRA_DIR}"
            ./bin/docker-proxy-post.bash
            cd - >/dev/null
        fi
    fi
done

echo ">>> All required infrastructures for '${TAP_GROUP}' are READY (INFRA_ID: ${INFRA_ID})."

# 6. Derive DEFAULT_MYSQL_INFRA and DEFAULT_PGSQL_INFRA for hooks
for INFRA_NAME in ${INFRAS}; do
    if [[ "${INFRA_NAME}" == *mysql* ]] || [[ "${INFRA_NAME}" == *mariadb* ]]; then
        export DEFAULT_MYSQL_INFRA="${DEFAULT_MYSQL_INFRA:-${INFRA_NAME}}"
    fi
    if [[ "${INFRA_NAME}" == *pgsql* ]] || [[ "${INFRA_NAME}" == *pgdb* ]]; then
        export DEFAULT_PGSQL_INFRA="${DEFAULT_PGSQL_INFRA:-${INFRA_NAME}}"
    fi
done

# 7. Execute group-specific setup hook if it exists
# This allows TAP groups to perform additional setup after all backends are running
SETUP_HOOK="${WORKSPACE}/test/tap/groups/${TAP_GROUP}/setup-infras.bash"
if [ ! -f "${SETUP_HOOK}" ]; then
    SETUP_HOOK="${WORKSPACE}/test/tap/groups/${BASE_GROUP}/setup-infras.bash"
fi

if [ -f "${SETUP_HOOK}" ]; then
    echo ">>> Executing group setup hook: ${SETUP_HOOK}"
    "${SETUP_HOOK}"
fi

# ensure-infras.bash completed successfully
