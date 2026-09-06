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

# md5-auth user for #5865 md5 backend pass-through (pgsql-md5_passthrough-t).
# password_encryption MUST be set to 'md5' in the SAME psql session BEFORE CREATE USER so
# pg_authid.rolpassword is stored as an 'md5...' hash (not a SCRAM verifier). pg_hba.conf grants
# 'md5user' the md5 method (above the scram-sha-256 catch-all). Password mirrors the loop above
# (password == username) so tests can supply the known plaintext.
echo "Creating md5-auth user: md5user"
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "SET password_encryption = 'md5';" -c "DROP USER IF EXISTS md5user;" -c "CREATE USER md5user WITH PASSWORD 'md5user';"
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "CREATE DATABASE md5user;"
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT ALL PRIVILEGES ON DATABASE md5user TO md5user;"
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT pg_write_server_files,pg_read_server_files TO md5user;"
docker exec "${CONTAINER}" psql -X -Upostgres -dmd5user -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT ALL ON SCHEMA public TO md5user;"
docker exec "${CONTAINER}" psql -X -Upostgres -dpostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "GRANT ALL ON SCHEMA public TO md5user;"

# Cleartext-password user for the md5_secret/AUTH_REQ_PASSWORD regression (pgsql-md5_passthrough-t).
# Stored as an md5 hash (like md5user) so the test can read pg_authid.rolpassword and hand that exact
# hash to ProxySQL -- but pg_hba grants 'cleartextuser' the 'password' (CLEARTEXT) method, so the backend
# answers with AuthenticationCleartextPassword. That mismatch is the crash condition.
# No database and no GRANTs, unlike md5user: the backend connection for this role is REQUIRED to
# fail at authentication, so it never executes anything and needs no privileges. The test reads
# its pg_authid.rolpassword over the superuser connection.
echo "Creating cleartext-password user: cleartextuser"
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "SET password_encryption = 'md5';" -c "DROP USER IF EXISTS cleartextuser;" -c "CREATE USER cleartextuser WITH PASSWORD 'cleartextuser';"

# Ensure postgres user has the ROOT_PASSWORD
docker exec "${CONTAINER}" psql -X -Upostgres -c "SET client_min_messages = 'error';" -c "SET lock_timeout = '10s';" -c "ALTER USER postgres WITH PASSWORD '${ROOT_PASSWORD}';"

sleep 1

printf "\n[$(date)] PgSQL Provisioning COMPLETE!\n"
