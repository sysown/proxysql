#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying PostgreSQL 17 streaming replication"
echo "  (1 primary + 2 replicas, master-slave topology)"
echo "========================================================================"

# Passed in via docker-compose environment. (Unlike the MySQL GR reference,
# INFRA is not needed here: PG has no report_host equivalent and no per-infra
# role is provisioned.)
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"

# ---------------------------------------------------------------------------
# 1. Detect the pre-baked PostgreSQL version (unpacked at image-build time).
# ---------------------------------------------------------------------------
PG_VERSION=$(ls /home/pguser/opt/postgresql/ 2>/dev/null | head -1)
if [ -z "${PG_VERSION}" ]; then
    echo "ERROR: No unpacked PostgreSQL found in /home/pguser/opt/postgresql/"
    exit 1
fi
echo "Using PostgreSQL version: ${PG_VERSION}"

# ---------------------------------------------------------------------------
# 2. Deploy the replication sandbox as pguser (initdb refuses to run as root).
#    --base-port / --bind-address / -c are silently ignored by the postgresql
#    provider (spike §5); ports are auto-derived to 16710/16711/16712 for 17.10.
# ---------------------------------------------------------------------------
su - pguser -c "dbdeployer deploy replication ${PG_VERSION} --provider=postgresql --topology=master-slave --nodes=3"

# Locate the sandbox tree (dbdeployer sandboxes command is unreliable for PG;
# enumerate the directory instead -- spike §6).
SBASE=$(ls -d /home/pguser/sandboxes/postgresql_repl_* 2>/dev/null | head -1)
if [ -z "${SBASE}" ]; then
    echo "ERROR: PostgreSQL replication sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SBASE}"

# Derive the port map from the sandbox dir name (postgresql_repl_<baseport>).
BASE_PORT="$(basename "${SBASE}")"
BASE_PORT="${BASE_PORT##*_}"
PRIMARY_PORT="${BASE_PORT}"
REPLICA1_PORT="$((BASE_PORT + 1))"
REPLICA2_PORT="$((BASE_PORT + 2))"
echo "Ports -> primary=${PRIMARY_PORT} replica1=${REPLICA1_PORT} replica2=${REPLICA2_PORT}"

# ---------------------------------------------------------------------------
# 3. Post-deploy config injection (spike §5): the provider ignores -c flags, so
#    append overrides directly to each node's postgresql.conf, widen pg_hba.conf
#    for cross-container access, then restart each node.
# ---------------------------------------------------------------------------
echo "Injecting postgresql.conf / pg_hba.conf overrides on all 3 nodes..."
for n in primary replica1 replica2; do
    echo "  - stopping ${n}"
    su - pguser -c "'${SBASE}/${n}/stop'"

    cat >> "${SBASE}/${n}/data/postgresql.conf" <<EOF

# --- injected by infra-dbdeployer-pgsql17-repl entrypoint ---
listen_addresses = '*'
shared_preload_libraries = 'pg_stat_statements'
pg_stat_statements.track = all
max_connections = 200
EOF

    # Widen host-based auth so other containers on the Docker network can reach
    # the node. 'md5' transparently negotiates SCRAM when the stored verifier is
    # SCRAM (PG >= 10), so real password auth is exercised for app roles.
    # Replication connections keep 'trust' (replicas stream as postgres with no
    # password via primary_conninfo) so setting the postgres password below does
    # not break streaming.
    cat >> "${SBASE}/${n}/data/pg_hba.conf" <<EOF
# --- injected by infra-dbdeployer-pgsql17-repl entrypoint ---
host    all         all   0.0.0.0/0   md5
host    replication all   0.0.0.0/0   trust
EOF
done

echo "Restarting all 3 nodes..."
for n in primary replica1 replica2; do
    echo "  - starting ${n}"
    su - pguser -c "'${SBASE}/${n}/start'"
done

# ---------------------------------------------------------------------------
# 4. Wait until every node accepts connections (loopback trust auth).
# ---------------------------------------------------------------------------
PSQL_PRIMARY="psql -h 127.0.0.1 -p ${PRIMARY_PORT} -U postgres -d postgres"
for spec in "primary:${PRIMARY_PORT}" "replica1:${REPLICA1_PORT}" "replica2:${REPLICA2_PORT}"; do
    NAME="${spec%%:*}"; PORT="${spec##*:}"
    echo -n "Waiting for ${NAME} on port ${PORT}..."
    MAX_WAIT=60; COUNT=0
    while ! psql -h 127.0.0.1 -p "${PORT}" -U postgres -d postgres -tAc "SELECT 1" >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; exit 1; fi
        echo -n "."; sleep 1; COUNT=$((COUNT + 1))
    done
    echo " OK"
done

# ---------------------------------------------------------------------------
# 5. Wait for streaming replication to be established.
#    primary: pg_is_in_recovery()=f AND 2 streaming walsenders
#    replicas: pg_is_in_recovery()=t
# ---------------------------------------------------------------------------
echo -n "Waiting for replication to stream..."
MAX_WAIT=60; COUNT=0
while true; do
    PRIM_REC=$(psql -h 127.0.0.1 -p "${PRIMARY_PORT}" -U postgres -d postgres -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || echo "err")
    R1_REC=$(psql -h 127.0.0.1 -p "${REPLICA1_PORT}" -U postgres -d postgres -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || echo "err")
    R2_REC=$(psql -h 127.0.0.1 -p "${REPLICA2_PORT}" -U postgres -d postgres -tAc "SELECT pg_is_in_recovery();" 2>/dev/null || echo "err")
    STREAMING=$(psql -h 127.0.0.1 -p "${PRIMARY_PORT}" -U postgres -d postgres -tAc \
        "SELECT count(*) FROM pg_stat_replication WHERE state='streaming';" 2>/dev/null || echo "0")
    if [ "${PRIM_REC}" = "f" ] && [ "${R1_REC}" = "t" ] && [ "${R2_REC}" = "t" ] && [ "${STREAMING}" = "2" ]; then
        echo " OK (primary=f, replicas=t, ${STREAMING} streaming)"
        break
    fi
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT (primary=${PRIM_REC} r1=${R1_REC} r2=${R2_REC} streaming=${STREAMING})"
        exit 1
    fi
    echo -n "."; sleep 2; COUNT=$((COUNT + 2))
done

# ---------------------------------------------------------------------------
# 6. Provision roles / databases / extension on the PRIMARY only.
#    Physical streaming replication propagates all of this byte-for-byte to the
#    replicas (spike §8; brief: "creating on primary is sufficient").
# ---------------------------------------------------------------------------
echo "Provisioning roles / databases / pg_stat_statements on the primary..."
${PSQL_PRIMARY} -v ON_ERROR_STOP=1 <<SQL
SET client_min_messages = 'error';

-- App role: testuser / testuser  (LOGIN CREATEDB)
DROP ROLE IF EXISTS testuser;
CREATE ROLE testuser LOGIN CREATEDB PASSWORD 'testuser';

-- Monitor role for ProxySQL replication_hostgroups (matches pgsql-monitor_*).
DROP ROLE IF EXISTS monitor;
CREATE ROLE monitor LOGIN PASSWORD 'monitor';

-- Give the sandbox superuser a known password so Task 4's ProxySQL can log in
-- over TCP as 'postgres'. Value = ROOT_PASSWORD (sha256 of INFRA_ID, same
-- convention as the MySQL GR reference infra).
ALTER ROLE postgres WITH PASSWORD '${ROOT_PASSWORD}';
SQL

# testuser database (owner testuser) + public-schema grants (PG15+ locks public).
${PSQL_PRIMARY} -v ON_ERROR_STOP=1 -c "SET client_min_messages='error';" \
    -c "CREATE DATABASE testuser OWNER testuser;"
psql -h 127.0.0.1 -p "${PRIMARY_PORT}" -U postgres -d testuser -v ON_ERROR_STOP=1 \
    -c "SET client_min_messages='error';" -c "GRANT ALL ON SCHEMA public TO testuser;"
# Intentional second grant: the same grant against the 'postgres' database's
# public schema, since some tests use 'postgres' as their default DB (mirrors
# docker-pgsql16-single/bin/docker-pgsql-post.bash, which grants on both).
${PSQL_PRIMARY} -v ON_ERROR_STOP=1 \
    -c "SET client_min_messages='error';" -c "GRANT ALL ON SCHEMA public TO testuser;"

# pg_stat_statements extension in each app database (replicates to standbys).
for DB in postgres testuser; do
    psql -h 127.0.0.1 -p "${PRIMARY_PORT}" -U postgres -d "${DB}" -v ON_ERROR_STOP=1 \
        -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
done

# ---------------------------------------------------------------------------
# 7. Verify pg_stat_statements is queryable on the replicas too (extension
#    objects arrive via streaming replication; the .so is preloaded on each node).
# ---------------------------------------------------------------------------
echo -n "Verifying pg_stat_statements on replicas..."
MAX_WAIT=30; COUNT=0
while true; do
    R1_OK=$(psql -h 127.0.0.1 -p "${REPLICA1_PORT}" -U postgres -d postgres -tAc \
        "SELECT count(*) >= 0 FROM pg_stat_statements;" 2>/dev/null || echo "f")
    R2_OK=$(psql -h 127.0.0.1 -p "${REPLICA2_PORT}" -U postgres -d postgres -tAc \
        "SELECT count(*) >= 0 FROM pg_stat_statements;" 2>/dev/null || echo "f")
    if [ "${R1_OK}" = "t" ] && [ "${R2_OK}" = "t" ]; then echo " OK"; break; fi
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT (replica1=${R1_OK} replica2=${R2_OK})"; exit 1
    fi
    echo -n "."; sleep 2; COUNT=$((COUNT + 2))
done

# ---------------------------------------------------------------------------
# 8. Signal readiness (consumed by docker-compose-init.bash).
# ---------------------------------------------------------------------------
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer PostgreSQL 17 replication is ready."
echo "  primary  : port ${PRIMARY_PORT}   (pg_is_in_recovery = f)"
echo "  replica1 : port ${REPLICA1_PORT}   (pg_is_in_recovery = t)"
echo "  replica2 : port ${REPLICA2_PORT}   (pg_is_in_recovery = t)"
echo "  roles    : testuser/testuser (LOGIN CREATEDB), monitor/monitor,"
echo "             postgres/<ROOT_PASSWORD>"
echo "  pg_stat_statements: preloaded + created in postgres + testuser DBs"
echo "========================================================================"

# Keep the container alive.
exec sleep infinity
