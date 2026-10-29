#!/bin/bash
set -e
set -o pipefail
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT
set -a; . .env; set +a
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"

echo "Destroying CI Infra Cluster '${INFRA}' (Project: ${COMPOSE_PROJECT})..."
docker compose -p "${COMPOSE_PROJECT}" down -v
