#!/bin/bash

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

#if [ -z "${MYSQL_VERSION}" ]; then
	set -a
	source .env
	export MYSQL_VERSION
	export USE_SSL
	export REQUIRE_SSL
#fi

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

docker-compose --profile mysql --profile debezium down -v


echo "================================================================================="
echo "Done."
echo "================================================================================="
