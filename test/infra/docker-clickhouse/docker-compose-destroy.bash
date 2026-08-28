#!/bin/bash
set -e
set -o pipefail

# make sure we have correct cwd
pushd $(dirname $0)
trap popd EXIT

. constants

export INFRA=$(basename ${PWD})
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

printf "$BRIGHT"
printf "##################################################################################\n"
printf "# Stopping infra '$INFRA'\n"
printf "##################################################################################\n"
printf "$NORMAL"

# dump logs
mkdir -p $INFRA_LOGS_PATH/$INFRA &>/dev/null
chmod -R 777 $INFRA_LOGS_PATH/$INFRA
if [[ ${DOCKER_MODE} = swarm ]]; then
    docker service logs $(docker ps \ grep -Po "${INFRA}.clickhouse.*") &> $INFRA_LOGS_PATH/$INFRA/docker-clickhouse.log
else
    docker logs $(docker ps \ grep -Po "${INFRA}.clickhouse.*") &> $INFRA_LOGS_PATH/$INFRA/docker-clickhouse.log
fi

# stop infra
if [[ ${DOCKER_MODE} = swarm ]]; then
    docker stack rm $INFRA
else
    docker compose down -v --remove-orphans
#    docker compose stop
#    docker compose rm -f
#    docker volume prune -f
#    docker network prune -f
fi

printf "$POWDER_BLUE$BRIGHT[$(date)] Deprovisioning COMPLETE!$NORMAL\n"

