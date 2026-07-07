#!/bin/bash

# make sure we have correct cwd
pushd $(dirname $0) &>/dev/null
trap 'popd &>/dev/null' EXIT

#if [ -z "${MYSQL_VERSION}" ]; then
	set -a
	source .env
	export MYSQL_VERSION
	export USE_SSL
	export HAVE_SSL
#fi

export DOCKER_MODE=compose

if [ -z "${INFRA}" ]; then
	export INFRA=${PWD##*/}
fi
export INFRA_LOGS_PATH=${INFRA_LOGS_PATH:-${PWD}/logs}

echo "================================================================================"
echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
echo "Initializing CI Infra '${INFRA}' mode '${DOCKER_MODE}' ..."
echo MYSQL_VERSION: $MYSQL_VERSION
echo SSL: $SSL
echo USE_SSL: $USE_SSL HAVE_SSL: $HAVE_SSL REQUIRE_SSL: $REQUIRE_SSL
echo DEBEZIUM: $DEBEZIUM
echo INFRA_LOGS_PATH: $INFRA_LOGS_PATH
echo REPL_TESTS_PATH: $REPL_TESTS_PATH
echo REPL_INFRA_DATADIR: $REPL_INFRA_DATADIR
echo "================================================================================"

for CONTAINER in $( envsubst < docker-compose.yml | grep "hostname" | grep -v '#' | tr '.' ' ' | awk '{ print $2 }'); do

	# re-create directories
	dir_path="${INFRA_LOGS_PATH}/${INFRA}/${CONTAINER}/${MYSQL_VERSION}_${SSL}"
	rm -rf "$dir_path"
	mkdir -p "$dir_path"
	chmod 777 "$dir_path"

done

if [[ ${DEBEZIUM} = "debezium" ]]; then
	docker-compose --profile mysql --profile debezium up -d
else
	docker-compose --profile mysql up -d
fi

# pass 'no_binlog_checksum' if it's required
./bin/docker-mysql-post.bash $1
./bin/docker-proxy-post.bash

echo "================================================================================"
echo "Done."
echo "================================================================================"
