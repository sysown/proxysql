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

# 1. STOP ANY EXISTING CONTAINERS FOR THIS PROJECT
# This ensures that we can safely wipe the data directories on the host
echo "Stopping existing containers for project ${COMPOSE_PROJECT}..."
if [ -f "./docker-compose-destroy.bash" ]; then
    ./docker-compose-destroy.bash >/dev/null 2>&1 || true
else
    $COMPOSE_CMD -p "${COMPOSE_PROJECT}" down -v --remove-orphans >/dev/null 2>&1 || true
fi

# 2. Infrastructure-specific preparation (logs/data)
# We wipe the directory to ensure a clean slate for database engines
for CONTAINER in $(grep 'hostname:' docker-compose.yml | grep -v '#' | tr '.' ' ' | awk '{ print $2 }' | cut -d'.' -f1); do
    LOG_DIR="${INFRA_LOGS_PATH}/${COMPOSE_PROJECT}/${CONTAINER}"
    echo "Preparing clean log/data directory: ${LOG_DIR}"
    $SUDO rm -rf "${LOG_DIR}"
    $SUDO mkdir -p "${LOG_DIR}"
    $SUDO chmod -R 777 "${LOG_DIR}"
    # Specific fix for engines like postgres that need ownership
    if [[ "${INFRA}" == *pgsql* ]]; then
        $SUDO chown -R 999:999 "${LOG_DIR}"
    fi
done

# 3. Inject dynamic ROOT_PASSWORD into Orchestrator configs
if [ -d "./conf/orchestrator" ]; then
    echo "Injecting ROOT_PASSWORD into Orchestrator configurations..."
    find ./conf/orchestrator -name "orchestrator.conf.json" -exec sed -i "s/\"MySQLTopologyPassword\": \".*\"/\"MySQLTopologyPassword\": \"${ROOT_PASSWORD}\"/g" {} +
fi

# 4. PostgreSQL SSL setup
if [ -f ./conf/pgsql/ssl/server.key ]; then
    $SUDO chmod 0640 ./conf/pgsql/ssl/server.key 2>/dev/null || true
    $SUDO chown 0:999 ./conf/pgsql/ssl/* 2>/dev/null || true
fi

# 5. Local log directory fix for some compose files
if grep -q "./log/" docker-compose.yml; then
    mkdir -p ./log
    chmod 777 ./log
    for DIR in $(grep "./log/" docker-compose.yml | awk -F'[:/]' '{print $3}' | sort -u); do
        mkdir -p "./log/${DIR}"
        chmod 777 "./log/${DIR}"
    done
fi

# 6. Create a temporary env file for docker-compose to ensure it sees our variables
ENV_FILE=".env.isolated.${INFRA_ID}"
cat <<ENVEOF > "${ENV_FILE}"
INFRA_ID=${INFRA_ID}
ROOT_PASSWORD=${ROOT_PASSWORD}
INFRA=${INFRA}
COMPOSE_PROJECT=${COMPOSE_PROJECT}
INFRA_LOGS_PATH=${INFRA_LOGS_PATH}
ENVEOF

# 7. START CONTAINERS
if ! $COMPOSE_CMD --env-file .env --env-file "${ENV_FILE}" -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; rm -f "${ENV_FILE}"; exit 1
fi
rm -f "${ENV_FILE}"

if [ -f /.dockerenv ]; then
        RUNNER_ID=$(hostname)
        docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

# 8. Run post-scripts if they exist
sleep 5 # wait a bit for engines to start
[ -f ./bin/docker-wait-pgsql.bash ] && ./bin/docker-wait-pgsql.bash
[ -f ./bin/docker-mysql-post.bash ] && ./bin/docker-mysql-post.bash
[ -f ./bin/docker-pgsql-post.bash ] && ./bin/docker-pgsql-post.bash
[ -f ./bin/docker-orchestrator-post.bash ] && ./bin/docker-orchestrator-post.bash
[ -f ./bin/docker-proxy-post.bash ] && ./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
