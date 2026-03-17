#!/bin/bash
set -e
set -o pipefail

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

set -a

. .env

export DOCKER_MODE=compose

export INFRA=${PWD##*/}
if [ -n "${INFRA_ID}" ]; then
    export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"
else
    export COMPOSE_PROJECT="${INFRA}"
fi
export INFRA="${COMPOSE_PROJECT}"

export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo "================================================================================="
echo "Destroying CI Infra '${INFRA}' mode '${DOCKER_MODE}' (Project: ${COMPOSE_PROJECT}) ..."
echo "================================================================================="

if [[ ${DOCKER_MODE} = swarm ]]; then
	docker stack rm ${COMPOSE_PROJECT}
elif [[ ${DOCKER_MODE} = k8s ]]; then
	kubectl delete -f <(eval "echo \"$(cat k8s-*.yml)\"")
	ps aux | grep kubectl | grep port-forward | grep ${COMPOSE_PROJECT} | awk '{ print $2 }' | xargs -r -n1 kill -9
	kubectl delete namespace ${COMPOSE_PROJECT}
else
	docker compose -p "${COMPOSE_PROJECT}" down -v
fi

echo "================================================================================="
echo "Done."
echo "================================================================================="
