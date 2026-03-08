#!/bin/bash
set -e
set -o pipefail
. constants

CONTAINER="${COMPOSE_PROJECT}-pgdb1-1"

printf "[$(date)] Waiting for PgSQL service (Container: ${CONTAINER}) "
MAX_WAIT=120
COUNT=0
while true; do
  # Use Unix socket (trust) for wait check
  if docker exec "${CONTAINER}" pg_isready -Upostgres > /dev/null 2>&1; then
    echo " OK."
    break
  fi
  printf "."
  sleep 1
  COUNT=$((COUNT+1))
  if [ $COUNT -gt $MAX_WAIT ]; then echo " TIMEOUT"; exit 1; fi
done

printf "\n[$(date)] PgSQL service is now ACTIVE\n"

# SSL Connectivity tests - using docker exec via localhost to trigger network path (scram-sha-256)
# We use PGPASSWORD because host connections require it
export PGPASSWORD="${ROOT_PASSWORD}"

echo -n "[$(date)] Connecting sslmode=disable .. "
docker exec -e PGSSLMODE=disable -e PGPASSWORD="${ROOT_PASSWORD}" "${CONTAINER}" psql -h localhost -Upostgres -c "\conninfo" 2>&1 | grep '^SSL' >/dev/null && echo FAIL || echo OK

echo -n "[$(date)] Connecting sslmode=prefer ... "
docker exec -e PGSSLMODE=prefer -e PGPASSWORD="${ROOT_PASSWORD}" "${CONTAINER}" psql -h localhost -Upostgres -c "\conninfo" 2>&1 | grep '^SSL' >/dev/null && echo OK || echo FAIL

unset PGPASSWORD
