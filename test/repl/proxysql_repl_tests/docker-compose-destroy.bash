#!/bin/bash

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

if [ -z "${MYSQL_VERSION}" ]; then
 	set -a
	. .env
  export MYSQL_VERSION=5.7
fi

export DOCKER_MODE=compose

if [ -z "${INFRA}" ]; then
    export INFRA=${PWD##*/}
fi
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo ""
echo "================================================================================"
echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
echo "Destroying CI Infra '${INFRA}' mode '${DOCKER_MODE}' ..."
echo "================================================================================="

docker-compose --profile "*" down -v --remove-orphans


echo "================================================================================="
echo "Done."
echo "================================================================================="
