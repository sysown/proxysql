#!/bin/bash

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

	docker compose down -v

echo "================================================================================="
echo "Done."
echo "================================================================================="
