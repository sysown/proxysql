#!/bin/bash

. ../env.sh

# make sure we are in correct folder
trap popd EXIT
pushd $WORKSPACE/src



echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> ProsySQL start ..."

(./proxysql --clickhouse-server --sqlite3-server --idle-threads -f -c "$DOCKER_SCRIPT_PATH/conf/proxysql/proxysql.cnf" -D $REGULAR_INFRA_DATADIR 2>&1) &

sleep 3 # give proxysql some time to start

echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> ProsySQL start DONE in ${SECONDS}s"

