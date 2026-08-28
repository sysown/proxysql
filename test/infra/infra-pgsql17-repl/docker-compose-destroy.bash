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
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo "================================================================================="
echo "Destroying CI Infra '${INFRA}' mode '${DOCKER_MODE}' ..."
echo "================================================================================="

if [[ ${DOCKER_MODE} = swarm ]]; then
	docker stack rm $INFRA
elif [[ ${DOCKER_MODE} = k8s ]]; then
	kubectl delete -f <(eval "echo \"$(cat k8s-*.yml)\"")
	ps aux | grep kubectl | grep port-forward | grep ${INFRA} | awk '{ print $2 }' | xargs -r -n1 kill -9
	kubectl delete namespace ${INFRA}
else
	docker compose down -v --remove-orphans
fi

echo "================================================================================="
echo "Done."
echo "================================================================================="
