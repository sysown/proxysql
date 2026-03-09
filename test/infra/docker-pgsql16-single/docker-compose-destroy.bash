#!/bin/bash
set -e
set -o pipefail

# make sure we have correct cwd
pushd $(dirname $0)
trap popd EXIT

if [ -f .env ]; then set -a; . .env; set +a; fi
if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID must be set"; exit 1; fi

export INFRA=${PWD##*/}
export COMPOSE_PROJECT="${INFRA}-${INFRA_ID}"

printf "##################################################################################\n"
printf "# 			Stopping PgSQL Docker instance: ${COMPOSE_PROJECT}		 #\n"
printf "##################################################################################\n"

docker compose -p "${COMPOSE_PROJECT}" down -v --remove-orphans
docker compose -p "${COMPOSE_PROJECT}" stop
docker compose -p "${COMPOSE_PROJECT}" rm -f

# No need to prune everything, just let it be. Pruning might affect other runs.

printf "[$(date)] Deprovisioning COMPLETE! Project: ${COMPOSE_PROJECT}\n"
