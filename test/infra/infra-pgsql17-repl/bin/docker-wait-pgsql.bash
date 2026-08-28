#!/bin/bash
set -o pipefail
[ -f .env ] && . .env

PRIMARY_CONTAINER="${COMPOSE_PROJECT}-pgdb1-1"

echo -n "[$(date)] Waiting for PgSQL Primary (${PRIMARY_CONTAINER}) service "
MAX_WAIT=60
COUNT=0
while true; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo -e "\nERROR: TIMEOUT after ${MAX_WAIT} seconds waiting for ${PRIMARY_CONTAINER}"
        exit 1
    fi

    # 1. Check if container is actually running
    STATE=$(docker inspect -f '{{.State.Running}}' "${PRIMARY_CONTAINER}" 2>/dev/null || echo "false")
    if [ "${STATE}" != "true" ]; then
        echo -e "\nERROR: Container ${PRIMARY_CONTAINER} is NOT running!"
        echo ">>> Container Logs:"
        docker logs "${PRIMARY_CONTAINER}" | tail -n 20
        exit 1
    fi

    # 2. Check if service is ready
    if docker exec "${PRIMARY_CONTAINER}" env PGPASSWORD="${ROOT_PASSWORD}" psql -h127.0.0.1 -p5432 -Upostgres -c "select 1;" > /dev/null 2>&1; then
        echo -e "\n[$(date)] PgSQL Primary service is now ACTIVE"
        break
    fi

    echo -n "."
    sleep 2
    COUNT=$((COUNT+2))
done
