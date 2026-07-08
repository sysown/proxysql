#!/bin/bash
if [ -z "${INFRA_ID}" ]; then
    export INFRA_ID=$(basename $(dirname $(pwd)) | sed 's/infra-//; s/docker-//')
fi
if [ -z "${INFRA_ID}" ] || [ "${INFRA_ID}" = "." ]; then
    export INFRA_ID="dev-$USER"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

set -e
set -o pipefail

SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

[[ $(ps -o command= $(ps -o ppid= $$)) =~ timeout ]] || exec timeout -v -s 9 ${TIMEOUT:-600} "${BASH_SOURCE}" "$@"

pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
SAVED_INFRA_ID="${INFRA_ID}"
set -a; . .env; set +a
export INFRA_ID="${SAVED_INFRA_ID}"

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

if [ -n "$($COMPOSE_CMD -p "${COMPOSE_PROJECT}" ps -q 2>/dev/null)" ]; then
    echo "ERROR: Containers for project ${COMPOSE_PROJECT} are already running."
    echo "Please run teardown first."
    exit 1
fi

echo "Scanning for volumes in docker-compose.yml..."
MOUNTED_PATHS=$(grep -E '\$\{INFRA_LOGS_PATH\}|\./log/' docker-compose.yml | grep -vE "\.crt|\.key" | awk -F: '{print $1}' | sed 's/^[[:space:]-]*//' | sort -u || true)

for RAW_PATH in ${MOUNTED_PATHS}; do
    if [[ "${RAW_PATH}" == "./conf/"* ]]; then continue; fi
    eval "ACTUAL_PATH=${RAW_PATH}"
    if [ -d "${ACTUAL_PATH}" ] && [ "$(ls -A "${ACTUAL_PATH}" 2>/dev/null)" ]; then
        echo "ERROR: Directory '${ACTUAL_PATH}' is not empty."
        echo "Please run teardown/cleanup first."
        exit 1
    fi
    echo "Preparing directory: ${ACTUAL_PATH}"
    $SUDO mkdir -p "${ACTUAL_PATH}"
    $SUDO chmod -R 777 "${ACTUAL_PATH}"
done

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

CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"
echo -n "Waiting for dbdeployer to finish deployment..."
MAX_WAIT=120
COUNT=0
while ! docker exec "${CONTAINER}" test -f /tmp/dbdeployer_ready 2>/dev/null; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT"
        echo ">>> Container Logs:"
        docker logs "${CONTAINER}" | tail -n 50
        exit 1
    fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT + 2))
done
echo " OK"

[ -f ./bin/docker-mysql-post.bash ] && ./bin/docker-mysql-post.bash
[ -f ./bin/docker-proxy-post.bash ] && ./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
