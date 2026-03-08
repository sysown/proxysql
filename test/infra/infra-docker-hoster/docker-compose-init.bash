#!/bin/bash
# Derive Workspace relative to script
SCRIPT_DIR=""
REPO_ROOT=""
export WORKSPACE=""


# relaunch self with timeout
[[ $(ps -o command= $(ps -o ppid= $$)) =~ timeout ]] || exec timeout -v -s 9 ${TIMEOUT:-300} "${BASH_SOURCE}" "$@"

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

set -a

. .env

export DOCKER_MODE=compose

export INFRA=${PWD##*/}
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo "================================================================================"
echo "Initializing CI Infra '${INFRA}' mode '${DOCKER_MODE}' ..."
echo "================================================================================"

	docker compose down
	docker compose up -d

echo "================================================================================"
echo "Done."
echo "================================================================================"
