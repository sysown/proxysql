#!/bin/bash
# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# SUDO helper: empty if root
SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi


# make sure we have correct cwd
pushd $(dirname $0)
trap popd EXIT

. constants

export INFRA=$(basename ${PWD})
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo "========================================================"
free
echo "========================================================"
ss -ntpl | grep docker
echo "========================================================"
echo "Starting infra '$INFRA' ..."
echo "========================================================"

# prep logs
mkdir -p $INFRA_LOGS_PATH/$INFRA &>/dev/null
chmod -R 777 $INFRA_LOGS_PATH/$INFRA

# start infra
if [[ ${DOCKER_MODE} = swarm ]]; then
#    docker save clickhouse/clickhouse-server:latest | ssh root@10.71.56.15 'docker load'
#    docker save clickhouse/clickhouse-server:latest | ssh root@10.68.234.143 'docker load'
    docker stack deploy -c <(docker compose config 2>/dev/null) --resolve-image="never" $INFRA
else
    docker compose up -d
fi

./bin/docker-proxy-post.bash

sleep 30
echo "========================================================"
echo "Starting infra '$INFRA' ... DONE."
echo "========================================================"
free
echo "========================================================"
ss -ntpl | grep docker
echo "========================================================"
echo "Clickhouse Server Version: $(clickhouse-client -h127.0.0.1 --port=19000 -q 'select VERSION();')"
echo "========================================================"
