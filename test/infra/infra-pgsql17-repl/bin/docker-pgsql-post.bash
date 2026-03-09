#!/bin/bash
set -e
set -o pipefail

[ -f .env ] && . .env

PRIMARY_CONTAINER="${COMPOSE_PROJECT}-pgdb1-1"
# Standard CI replication credentials
REPLICATION_USER="repluser"
REPLICATION_PASSWORD="${ROOT_PASSWORD}"

PGUSERS="testuser monitor"

echo "[$(date)] PgSQL Primary Provisioning (${PRIMARY_CONTAINER}) ..."

# Helper for docker exec psql
run_psql() {
    docker exec "${PRIMARY_CONTAINER}" env PGPASSWORD="${ROOT_PASSWORD}" psql -h127.0.0.1 -p5432 -Upostgres "$@"
}

# 1. Create replication user on primary
echo "[$(date)] Creating replication user '${REPLICATION_USER}' ..."
run_psql -c "DROP USER IF EXISTS ${REPLICATION_USER}; CREATE USER ${REPLICATION_USER} WITH REPLICATION ENCRYPTED PASSWORD '${REPLICATION_PASSWORD}';" > /dev/null

# 2. Create replication slots for each replica
echo "[$(date)] Creating replication slots ..."
for i in 2; do
    SLOT_NAME="replica_slot_${i}"
    run_psql -c "SELECT pg_drop_replication_slot('${SLOT_NAME}');" > /dev/null 2>&1 || true
    run_psql -c "SELECT pg_create_physical_replication_slot('${SLOT_NAME}');" > /dev/null
done

# 3. Create application users
echo "[$(date)] Creating application users ..."
for PGUSER in ${PGUSERS}; do
    run_psql -c "DROP USER IF EXISTS $PGUSER; CREATE USER $PGUSER WITH PASSWORD '$PGUSER';" > /dev/null
    run_psql -c "CREATE DATABASE $PGUSER;" > /dev/null 2>&1 || true
    run_psql -c "GRANT ALL PRIVILEGES ON DATABASE $PGUSER TO $PGUSER;" > /dev/null
    run_psql -c "GRANT ALL ON SCHEMA public TO $PGUSER;" > /dev/null 2>&1 || true
done

echo "[$(date)] PgSQL Provisioning COMPLETE!"
