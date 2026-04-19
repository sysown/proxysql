#!/bin/bash
set -e
set -o pipefail
. constants

CONTAINER="${COMPOSE_PROJECT}-pgdb1-1"
PGUSERS="root testuser monitor"

printf "[$(date)] PgSQL Provisioning (Container: ${CONTAINER}) ..."

# We execute commands as separate psql calls to avoid the "transaction block" error
for PGUSER in ${PGUSERS}; do
    echo "Creating user: $PGUSER"
    # Setting client_min_messages to error cleans up the notices for missing users
    docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "DROP USER IF EXISTS $PGUSER;" -c "CREATE USER $PGUSER WITH PASSWORD '$PGUSER';"
    docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "CREATE DATABASE $PGUSER;"
    docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT ALL PRIVILEGES ON DATABASE $PGUSER TO $PGUSER;"
    docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT pg_write_server_files,pg_read_server_files TO $PGUSER;"
    
    # CRITICAL: In PG 15+, public schema permissions are restricted. 
    # We must explicitly grant CREATE on public to the user in their own database.
    docker exec "${CONTAINER}" psql -X -Upostgres -d$PGUSER -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT ALL ON SCHEMA public TO $PGUSER;"
    
    # Also grant on the 'postgres' database since some tests use it as default
    docker exec "${CONTAINER}" psql -X -Upostgres -dpostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT ALL ON SCHEMA public TO $PGUSER;"
done

# Ensure postgres user has the ROOT_PASSWORD
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "ALTER USER postgres WITH PASSWORD '${ROOT_PASSWORD}';"

sleep 1

printf "\n[$(date)] PgSQL Provisioning COMPLETE!\n"
