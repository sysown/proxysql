#!/bin/bash

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

for CONTAINER in $(grep 'hostname:' docker-compose.yml | grep -v '#' | tr '.' ' ' | awk '{ print $2 }'); do
	rm -rf ${INFRA_LOGS_PATH}/${INFRA}/${CONTAINER}
	mkdir -p ${INFRA_LOGS_PATH}/${INFRA}/${CONTAINER}
	chmod -R 777 ${INFRA_LOGS_PATH}/${INFRA}/${CONTAINER}
done

if [[ ${DOCKER_MODE} = swarm ]]; then
	docker stack deploy -c <(docker compose config 2>/dev/null) --resolve-image="never" $INFRA
elif [[ ${DOCKER_MODE} = k8s ]]; then
	kubectl create namespace ${INFRA} 2>&1 | grep -v 'already exists'
	kubectl apply -f <(eval "echo \"$(cat k8s-*.yml)\"")
else
	docker compose up -d
#	sleep 10
#	for HN in $(grep 'hostname:' docker-compose.yml | grep -v '#' | tr '.' ' ' | awk '{ print $2 }'); do
#		while [[ "$(docker logs ${INFRA}-${HN}-1 | tail -1)" =~ "Switching to dedicated user" ]]; do
#			docker compose restart ${HN}
#			sleep 10
#		done
#	done
fi

./bin/docker-mysql-post.bash
./bin/docker-orchestrator-post.bash
./bin/docker-proxy-post.bash $1

sudo chmod 777 ${REGULAR_INFRA_DATADIR:-$INFRA_LOGS_PATH}/
for CONTAINER in $(docker ps | grep -Po "${INFRA}.mysql.*"); do
	sudo chmod 777 ${REGULAR_INFRA_DATADIR:-$INFRA_LOGS_PATH}/dbservers-cert-bundle.pem || true
	docker cp ${CONTAINER}:/var/lib/mysql/ca.pem - | tar -Ox | sed 's/\x0//g' >> ${REGULAR_INFRA_DATADIR:-$INFRA_LOGS_PATH}/dbservers-cert-bundle.pem
done

echo "================================================================================"
echo "Done."
echo "================================================================================"
