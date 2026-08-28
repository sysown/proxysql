#!/bin/bash
set -e
set -o pipefail
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT
set -a; . .env; set +a
if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi
export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"

echo "Destroying CI Infra Cluster '${INFRA}' (Project: ${COMPOSE_PROJECT})..."
docker compose -p "${COMPOSE_PROJECT}" down -v
