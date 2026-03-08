#!/bin/bash
set -e
set -o pipefail

# make sure we have correct cwd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
set -a; . .env; set +a

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${WORKSPACE}/ci_infra_logs}

echo "Initializing CI Clickhouse Infra '${INFRA}' (Project: ${COMPOSE_PROJECT})"

LOG_DIR="${INFRA_LOGS_PATH}/${COMPOSE_PROJECT}/clickhouse"
sudo rm -rf "${LOG_DIR}"
sudo mkdir -p "${LOG_DIR}"
sudo chmod -R 777 "${LOG_DIR}"

if ! docker compose -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; exit 1
fi

if [ -f /.dockerenv ]; then
        RUNNER_ID=$(hostname)
        docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

./bin/docker-proxy-post.bash
