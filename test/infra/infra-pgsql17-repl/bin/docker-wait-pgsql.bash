#!/bin/bash
set -o pipefail

[ -f .env ] && . .env

PRIMARY_CONTAINER="${COMPOSE_PROJECT}-pgdb1-1"

printf "[$(date)] Waiting for PgSQL Primary (${PRIMARY_CONTAINER}) service "
MAX_WAIT=60
COUNT=0
RC=1
while [ $RC != 0 ]; do
  if [ $COUNT -ge $MAX_WAIT ]; then
    echo " TIMEOUT after ${MAX_WAIT} seconds"
    exit 1
  fi
  sleep 1
  printf "."
  docker exec "${PRIMARY_CONTAINER}" env PGPASSWORD="${ROOT_PASSWORD}" psql -h127.0.0.1 -p5432 -Upostgres -c "select 1;" > /dev/null 2>&1
  RC=$?
  COUNT=$((COUNT+1))
done
printf "\n[$(date)] PgSQL Primary service is now ACTIVE\n"
