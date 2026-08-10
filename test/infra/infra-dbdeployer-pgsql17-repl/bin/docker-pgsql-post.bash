#!/bin/bash
# Host-side verification of the dbdeployer PostgreSQL replication backend.
# Provisioning (roles/databases/extension) happens inside the container's
# entrypoint; this script is VERIFICATION-ONLY. It asserts:
#   - all 3 nodes are reachable and report the expected recovery state (f/t/t)
#   - pg_stat_statements is queryable on every node
#   - testuser can authenticate over TCP using its password
set -e
set -o pipefail
[ -f .env ] && . .env

CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"

PRIMARY_PORT="${PG_PRIMARY_PORT:-16710}"
REPLICA1_PORT="${PG_REPLICA1_PORT:-16711}"
REPLICA2_PORT="${PG_REPLICA2_PORT:-16712}"

# psql runs INSIDE the container (image bakes psql onto PATH); connect over
# loopback (trust) as postgres for the recovery/extension assertions.
pg() {
    local port="$1"; shift
    docker exec "${CONTAINER}" psql -h 127.0.0.1 -p "${port}" -U postgres -d postgres -tAc "$1"
}

printf "[%s] PgSQL replication verification (Container: %s)\n" "$(date)" "${CONTAINER}"

# 1. Reachability + recovery state (primary=f, replicas=t).
declare -A EXPECT=( ["${PRIMARY_PORT}"]="f" ["${REPLICA1_PORT}"]="t" ["${REPLICA2_PORT}"]="t" )
for PORT in "${PRIMARY_PORT}" "${REPLICA1_PORT}" "${REPLICA2_PORT}"; do
    echo -n "  - node ${PORT}: waiting for connectivity..."
    MAX_WAIT=60; COUNT=0
    while ! pg "${PORT}" "SELECT 1" >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; exit 1; fi
        echo -n "."; sleep 2; COUNT=$((COUNT + 2))
    done
    REC=$(pg "${PORT}" "SELECT pg_is_in_recovery();")
    if [ "${REC}" != "${EXPECT[$PORT]}" ]; then
        echo " FAIL (pg_is_in_recovery=${REC}, expected ${EXPECT[$PORT]})"
        exit 1
    fi
    echo " OK (pg_is_in_recovery=${REC})"
done

# 2. pg_stat_statements queryable on every node.
for PORT in "${PRIMARY_PORT}" "${REPLICA1_PORT}" "${REPLICA2_PORT}"; do
    echo -n "  - node ${PORT}: pg_stat_statements..."
    if ! pg "${PORT}" "SELECT count(*) FROM pg_stat_statements;" >/dev/null 2>&1; then
        echo " FAIL (pg_stat_statements not queryable)"; exit 1
    fi
    echo " OK"
done

# 3. testuser TCP password login against every node.
for PORT in "${PRIMARY_PORT}" "${REPLICA1_PORT}" "${REPLICA2_PORT}"; do
    echo -n "  - node ${PORT}: testuser TCP password login..."
    if ! docker exec -e PGPASSWORD=testuser "${CONTAINER}" \
         psql -h 127.0.0.1 -p "${PORT}" -U testuser -d testuser -tAc "SELECT 1" >/dev/null 2>&1; then
        echo " FAIL (testuser could not authenticate)"; exit 1
    fi
    echo " OK"
done

printf "[%s] PgSQL replication verification COMPLETE (f/t/t + pg_stat_statements + testuser OK)\n" "$(date)"
