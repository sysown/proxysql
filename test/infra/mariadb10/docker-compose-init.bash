#!/bin/bash
set -e
set -o pipefail

# relaunch self with timeout
[[ $(ps -o command= $(ps -o ppid= $$)) =~ timeout ]] || exec timeout -v -s 9 ${TIMEOUT:-300} "${BASH_SOURCE}" "$@"

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
set -a
. .env
set +a

if [ -z "${INFRA_ID}" ]; then
    echo "Error: INFRA_ID must be set for Unified CI system."
    exit 1
fi

# Calculate Dynamic ROOT_PASSWORD
export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)

export DOCKER_MODE=compose

export INFRA=${PWD##*/}
if [ -n "${INFRA_ID}" ]; then
    export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
else
    export COMPOSE_PROJECT="${INFRA}"
fi
export INFRA="${COMPOSE_PROJECT}"

export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo "================================================================================"
echo "Initializing CI Infra '${INFRA}' mode '${DOCKER_MODE}' (Project: ${COMPOSE_PROJECT}) ..."
echo "================================================================================"

for CONTAINER in $(grep 'hostname:' docker-compose.yml | grep -v '#' | tr '.' ' ' | awk '{ print $2 }' | cut -d'.' -f1); do
    LOG_DIR="${INFRA_LOGS_PATH}/${COMPOSE_PROJECT}/${CONTAINER}"
    echo "Preparing log directory: ${LOG_DIR}"
    sudo rm -rf "${LOG_DIR}"
    sudo mkdir -p "${LOG_DIR}"
    sudo chmod -R 777 "${LOG_DIR}"
done

if [[ ${DOCKER_MODE} = swarm ]]; then
        docker stack deploy -c <(docker compose config 2>/dev/null) --resolve-image="never" ${COMPOSE_PROJECT}
elif [[ ${DOCKER_MODE} = k8s ]]; then
        kubectl create namespace ${COMPOSE_PROJECT} 2>&1 | grep -v 'already exists'
        kubectl apply -f <(eval "echo \"$(cat k8s-*.yml)\"")
else
    if ! docker compose -p "${COMPOSE_PROJECT}" up -d; then
        echo "ERROR: Docker Compose failed"; exit 1
    fi
fi

if [ -f /.dockerenv ]; then
        RUNNER_ID=$(hostname)
        docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

./bin/docker-mysql-post.bash
./bin/docker-proxy-post.bash "$1"

echo "================================================================================"
echo "Done."
echo "================================================================================"
