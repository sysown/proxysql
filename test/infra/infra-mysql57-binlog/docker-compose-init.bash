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

source "${REPO_ROOT}/test/infra/control/docker-fs-helper.bash"

set -e
set -o pipefail

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
echo "Scanning for volumes in docker-compose.yml..."
MOUNTED_PATHS=$(grep -E '\$\{INFRA_LOGS_PATH\}|\$\{COMPOSE_PROJECT\}' docker-compose.yml | grep -vE "\.crt|\.key" | awk -F: '{print $1}' | sed 's/^[[:space:]-]*//' | sort -u || true)

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
    mkdir -p "${ACTUAL_PATH}"
    docker_fs_exec "chmod -R 777 ." "${ACTUAL_PATH}"
done

# 3. Inject dynamic variables into Orchestrator configs
if [ -d "./conf/orchestrator" ]; then
    echo "Patching Orchestrator configurations..."
    find ./conf/orchestrator -name "orchestrator.conf.json" -exec sed -i "s/\"MySQLTopologyPassword\": \".*\"/\"MySQLTopologyPassword\": \"${ROOT_PASSWORD}\"/g" {} +
    find ./conf/orchestrator -name "orchestrator.conf.json" -exec sed -i "s/\${INFRA}/${INFRA}/g" {} +
fi

# 4. Create a temporary env file for docker-compose to ensure it sees our variables
ENV_FILE=".env.isolated.${INFRA_ID}"
cat <<ENVEOF > "${ENV_FILE}"
INFRA_ID=${INFRA_ID}
ROOT_PASSWORD=${ROOT_PASSWORD}
INFRA=${INFRA}
COMPOSE_PROJECT=${COMPOSE_PROJECT}
INFRA_LOGS_PATH=${INFRA_LOGS_PATH}
ENVEOF

# 5. START CONTAINERS
if ! $COMPOSE_CMD --env-file .env --env-file "${ENV_FILE}" -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; rm -f "${ENV_FILE}"; exit 1
fi
rm -f "${ENV_FILE}"

# 6. VERIFY ALL CONTAINERS STARTED SUCCESSFULLY
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

# 7. Run post-scripts if they exist
sleep 2 # wait a bit for engines to start
[ -f ./bin/docker-mysql-post.bash ] && ./bin/docker-mysql-post.bash
[ -f ./bin/docker-orchestrator-post.bash ] && ./bin/docker-orchestrator-post.bash
[ -f ./bin/docker-proxy-post.bash ] && ./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
