#!/bin/bash
set -e
set -o pipefail
. constants

TIMEOUT=0
TIMEOUT_LIMIT=300
CONTAINER="${COMPOSE_PROJECT}-pgdb1-1"

printf "[$(date)] Waiting for ProxySQL service to initialize (Host: proxysql)"
RC=1
while [ $RC != 0 ]
do
  if [ $TIMEOUT -gt $TIMEOUT_LIMIT ]
  then
    echo "\n[ERROR] Timeout of $TIMEOUT_LIMIT seconds reached while connecting to ProxySQL"
    exit 1
  fi
  sleep 1
  printf "."
  # We must run psql INSIDE the container to resolve 'proxysql' hostname
  docker exec -e PGPASSWORD='radmin' "${CONTAINER}" psql -X -hproxysql -p6132 -Uradmin -c "select 1;"
  RC=$?
  TIMEOUT=$((TIMEOUT+1))
done

printf "\n[$(date)] Configuring ProxySQL ...\n"

# Prepare the SQL by injecting dynamic password and correct hostname
PG_BACKEND="pgsql1.${INFRA}"
# We pipe the modified SQL directly into psql running inside the container
# REMOVED SET client_min_messages from here as ProxySQL Admin doesn't support it
sed "s/127.0.0.1/\\${PG_BACKEND}/g; s/15432/5432/g; s/'postgres',1/'${ROOT_PASSWORD}',1/g" $(pwd)/conf/proxysql/config.sql | \
    docker exec -i -e PGPASSWORD='radmin' "${CONTAINER}" psql -X -hproxysql -p6132 -Uradmin

# AGGRESSIVE PERSISTENCE: Save everything to DISK individually to avoid multi-statement issues
docker exec -e PGPASSWORD='radmin' "${CONTAINER}" psql -X -hproxysql -p6132 -Uradmin -c "SAVE PGSQL USERS TO DISK;"
docker exec -e PGPASSWORD='radmin' "${CONTAINER}" psql -X -hproxysql -p6132 -Uradmin -c "SAVE PGSQL SERVERS TO DISK;"
docker exec -e PGPASSWORD='radmin' "${CONTAINER}" psql -X -hproxysql -p6132 -Uradmin -c "SAVE PGSQL VARIABLES TO DISK;"

printf "[$(date)] Configuring ProxySQL DONE\n"
