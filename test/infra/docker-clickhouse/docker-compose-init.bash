#!/bin/bash
# RELIABLY CAPTURE INFRA_ID FROM ENVIRONMENT OR DIRECTORY NAME
if [ -z "${INFRA_ID}" ]; then
    export INFRA_ID=$(basename $(dirname $(pwd)) | sed 's/infra-//; s/docker-//')
fi
# Final safety: if INFRA_ID is still empty or ".", use a default
if [ -z "${INFRA_ID}" ] || [ "${INFRA_ID}" = "." ]; then
    export INFRA_ID="dev-$USER"
fi

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

set -e
set -o pipefail

# SUDO helper: empty if root
SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

# relaunch self with timeout
[[ $(ps -o command= $(ps -o ppid= $$)) =~ timeout ]] || exec timeout -v -s 9 ${TIMEOUT:-600} "${BASH_SOURCE}" "$@"

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

# Load .env but ensure INFRA_ID is preserved
if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
SAVED_INFRA_ID="${INFRA_ID}"
set -a; . .env; set +a
export INFRA_ID="${SAVED_INFRA_ID}"

# Docker Compose version helper - prefer plugin (v2)
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then 
    COMPOSE_CMD="docker-compose"
    if ! $COMPOSE_CMD version &>/dev/null; then
        echo "ERROR: Neither 'docker compose' nor 'docker-compose' found!"
        exit 1
    fi
fi

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${WORKSPACE}/ci_infra_logs}

echo "================================================================================"
echo "Initializing CI Infra '${INFRA}' (Project: ${COMPOSE_PROJECT}) ..."
echo "================================================================================"

# 1. VERIFY NO EXISTING CONTAINERS ARE RUNNING FOR THIS PROJECT
if [ -n "$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps -q 2>/dev/null)" ]; then
    echo "ERROR: Containers for project ${COMPOSE_PROJECT} are already running."
    echo "Please run teardown first."
    exit 1
fi

# 2. Infrastructure-specific preparation (logs/data)
# We extract host paths that appear to be for logs or data.
echo "Scanning for volumes in docker-compose.yml..."
# CRITICAL: Exclude .crt and .key files from auto-mkdir logic to prevent "directory vs file" conflicts
MOUNTED_PATHS=$(grep -E '\$\{INFRA_LOGS_PATH\}|\./log/' docker-compose.yml | grep -vE "\.crt|\.key" | awk -F: '{print $1}' | sed 's/^[[:space:]-]*//' | sort -u || true)

for RAW_PATH in ${MOUNTED_PATHS}; do
    # Skip relative paths that point to config files (e.g. ./conf/...)
    if [[ "${RAW_PATH}" == "./conf/"* ]]; then continue; fi
    
    # Expand variables like ${INFRA_LOGS_PATH} and ${COMPOSE_PROJECT}
    eval "ACTUAL_PATH=${RAW_PATH}"
    
    # Safety: Refuse to proceed if ACTUAL_PATH is a directory and is not empty
    if [ -d "${ACTUAL_PATH}" ] && [ "$(ls -A "${ACTUAL_PATH}" 2>/dev/null)" ]; then
        echo "ERROR: Directory '${ACTUAL_PATH}' is not empty."
        echo "Please run teardown/cleanup first."
        exit 1
    fi
    
    echo "Preparing directory: ${ACTUAL_PATH}"
    $SUDO mkdir -p "${ACTUAL_PATH}"
    $SUDO chmod -R 777 "${ACTUAL_PATH}"
    
    # Aggressive postgres fix: UID 999
    if [[ "${ACTUAL_PATH}" == *pgsql* ]] || [[ "${ACTUAL_PATH}" == *pgdb* ]]; then
        echo "Applying postgres ownership (999:999) to ${ACTUAL_PATH}"
        $SUDO chown -R 999:999 "${ACTUAL_PATH}"
    fi
done

# 3. Inject dynamic variables into Orchestrator configs
if [ -d "./conf/orchestrator" ]; then
    echo "Patching Orchestrator configurations..."
    find ./conf/orchestrator -name "orchestrator.conf.json" -exec sed -i "s/\"MySQLTopologyPassword\": \".*\"/\"MySQLTopologyPassword\": \"${ROOT_PASSWORD}\"/g" {} +
    find ./conf/orchestrator -name "orchestrator.conf.json" -exec sed -i "s/\${INFRA}/${INFRA}/g" {} +
fi

# 4. TRANSIENT SSL SETUP (Avoiding repo permission changes)
# We copy SSL files to a transient location and apply strict permissions there.
SSL_SRC="./conf/pgsql/ssl"
if [ -d "${SSL_SRC}" ]; then
    SSL_DST="${INFRA_LOGS_PATH}/${COMPOSE_PROJECT}/ssl"
    echo "Preparing transient SSL directory: ${SSL_DST}"
    $SUDO mkdir -p "${SSL_DST}"
    # SAFETY: Remove any directories that were mistakenly created with file names
    [ -d "${SSL_DST}/server.crt" ] && $SUDO rm -rf "${SSL_DST}/server.crt" || true
    [ -d "${SSL_DST}/server.key" ] && $SUDO rm -rf "${SSL_DST}/server.key" || true
    $SUDO cp -rp "${SSL_SRC}/." "${SSL_DST}/"
    # Strict permissions for postgres on the copies only
    $SUDO chmod 0640 "${SSL_DST}/server.key" 2>/dev/null || true
    $SUDO chown -R 0:999 "${SSL_DST}" 2>/dev/null || true
fi

# 5. Create a temporary env file for docker-compose to ensure it sees our variables
ENV_FILE=".env.isolated.${INFRA_ID}"
cat <<ENVEOF > "${ENV_FILE}"
INFRA_ID=${INFRA_ID}
ROOT_PASSWORD=${ROOT_PASSWORD}
INFRA=${INFRA}
COMPOSE_PROJECT=${COMPOSE_PROJECT}
INFRA_LOGS_PATH=${INFRA_LOGS_PATH}
ENVEOF

# 6. START CONTAINERS
if ! $COMPOSE_CMD --env-file .env --env-file "${ENV_FILE}" -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; rm -f "${ENV_FILE}"; exit 1
fi
rm -f "${ENV_FILE}"

# 7. VERIFY ALL CONTAINERS STARTED SUCCESSFULLY
echo "Verifying container health..."
PROJECT_CONTAINERS=$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps --format '{{.Name}}')
for C in ${PROJECT_CONTAINERS}; do
    STATE=$(docker inspect -f '{{.State.Running}}' "${C}" 2>/dev/null || echo "false")
    if [ "${STATE}" != "true" ]; then
        echo -e "\nERROR: Container ${C} failed to start!"
        echo ">>> Container Logs:"
        docker logs "${C}" | tail -n 50
        exit 1
    fi
done

if [ -f /.dockerenv ]; then
        RUNNER_ID=$(hostname)
        docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

# 8. Run post-scripts if they exist
sleep 2 # wait a bit for engines to start
[ -f ./bin/docker-wait-pgsql.bash ] && ./bin/docker-wait-pgsql.bash
[ -f ./bin/docker-mysql-post.bash ] && ./bin/docker-mysql-post.bash
[ -f ./bin/docker-pgsql-post.bash ] && ./bin/docker-pgsql-post.bash
[ -f ./bin/docker-orchestrator-post.bash ] && ./bin/docker-orchestrator-post.bash
[ -f ./bin/docker-proxy-post.bash ] && ./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
