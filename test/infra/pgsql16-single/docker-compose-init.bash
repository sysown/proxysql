#!/bin/bash
set -e
set -o pipefail

[[ $(ps -o command= $(ps -o ppid= $$)) =~ timeout ]] || exec timeout -v -s 9 ${TIMEOUT:-300} "${BASH_SOURCE}" "$@"

pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

if [ ! -f .env ]; then echo "Error: .env not found"; exit 1; fi
set -a; . .env; set +a

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi

# Calculate Dynamic ROOT_PASSWORD
export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)

export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${WORKSPACE:-.}/ci_infra_logs}

echo "Initializing CI Infra Cluster '${INFRA}' (Project: ${COMPOSE_PROJECT})"


# Prepare logs
for SERVICE in pgdb1; do
    LOG_DIR="${INFRA_LOGS_PATH}/${COMPOSE_PROJECT}/${SERVICE}"
    sudo rm -rf "${LOG_DIR}"
    sudo mkdir -p "${LOG_DIR}"
    sudo chmod -R 777 "${LOG_DIR}"
done

# Prepare SSL keys
sudo chmod 0640 ./conf/pgsql/ssl/server.key
sudo chown 0:999 conf/pgsql/ssl/*

if ! docker compose -p "${COMPOSE_PROJECT}" up -d; then
    echo "ERROR: Docker Compose failed"; exit 1
fi

if [ -f /.dockerenv ]; then
	RUNNER_ID=$(hostname)
	docker network connect "${INFRA_ID}_backend" "${RUNNER_ID}" || true
fi

export COMPOSE_PROJECT
./bin/docker-wait-pgsql.bash && ./bin/docker-pgsql-post.bash && ./bin/docker-proxy-post.bash
