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

# Docker Compose version helper
COMPOSE_CMD="docker compose"
if ! $COMPOSE_CMD version &>/dev/null; then COMPOSE_CMD="docker-compose"; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${WORKSPACE}/ci_infra_logs}

echo "================================================================================"
echo "Initializing CI Infra '${INFRA}' (Project: ${COMPOSE_PROJECT}) ..."
echo "================================================================================"

for CONTAINER in $(grep 'hostname:' docker-compose.yml | grep -v '#' | tr '.' ' ' | awk '{ print $2 }' | cut -d'.' -f1); do
    LOG_DIR="${INFRA_LOGS_PATH}/${COMPOSE_PROJECT}/${CONTAINER}"
    echo "Preparing log directory: ${LOG_DIR}"
    $SUDO mkdir -p "${LOG_DIR}"
    $SUDO chmod -R 777 "${LOG_DIR}"
done

# Infrastructure-specific setup
if [ -f ./conf/pgsql/ssl/server.key ]; then
    $SUDO chmod 0640 ./conf/pgsql/ssl/server.key 2>/dev/null || true
    $SUDO chown 0:999 ./conf/pgsql/ssl/* 2>/dev/null || true
fi

# Create a temporary env file for docker-compose to ensure it sees our variables
ENV_FILE=".env.isolated.${INFRA_ID}"
cat <<ENVEOF > "${ENV_FILE}"
INFRA_ID=${INFRA_ID}
ROOT_PASSWORD=${ROOT_PASSWORD}
INFRA=${INFRA}
COMPOSE_PROJECT=${COMPOSE_PROJECT}
INFRA_LOGS_PATH=${INFRA_LOGS_PATH}
ENVEOF

if ! $COMPOSE_CMD --env-file .env --env-file "${ENV_FILE}" -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; rm -f "${ENV_FILE}"; exit 1
fi
rm -f "${ENV_FILE}"

if [ -f /.dockerenv ]; then
        RUNNER_ID=$(hostname)
        docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

# Run post-scripts if they exist
[ -f ./bin/docker-wait-pgsql.bash ] && ./bin/docker-wait-pgsql.bash
[ -f ./bin/docker-mysql-post.bash ] && ./bin/docker-mysql-post.bash
[ -f ./bin/docker-pgsql-post.bash ] && ./bin/docker-pgsql-post.bash
[ -f ./bin/docker-orchestrator-post.bash ] && ./bin/docker-orchestrator-post.bash
[ -f ./bin/docker-proxy-post.bash ] && ./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
