#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env
# COMPOSE_PROJECT is exported by docker-compose-init.bash
CONTAINER="${COMPOSE_PROJECT}-clickhouse-1"

echo -n "Waiting for clickhouse container '${CONTAINER}' ..."
MAX_WAIT=60
COUNT=0
while true; do
    if docker exec "${CONTAINER}" clickhouse-client -q "SELECT 1" >/dev/null 2>&1; then
        echo " OK."
        break
    fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT+2))
    if [ $COUNT -gt $MAX_WAIT ]; then echo " FAILED"; exit 1; fi
done

echo -n "Clickhouse version: "
docker exec "${CONTAINER}" clickhouse-client -q "SELECT version()"
