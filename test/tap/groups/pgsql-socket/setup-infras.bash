#!/bin/bash
# pgsql-socket group setup hook.
#
# Runs after docker-pgsql16-single's docker-proxy-post.bash has inserted the
# default TCP-based pgsql_servers rows. We delete them and reinsert with
# `port=0` and `hostname='/var/run/postgresql-shared'` so that ProxySQL
# builds a libpq conninfo string that connects via the Unix-domain socket
# (the path that triggered the "invalid port number: \"0\"" bug).
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

if [ -z "${INFRA_ID}" ]; then
    echo "ERROR: INFRA_ID is not set."
    exit 1
fi

# Locate the ProxySQL container (docker-pgsql16-single already started it).
PROXY_HOST="proxysql"
PROXY_ADMIN_PORT="6032"
PROXY_ADMIN_USER="radmin"
PROXY_ADMIN_PASS="radmin"

# Wait for ProxySQL admin to be reachable; the previous infra start
# (legacy-g1 or pgsql-socket-g1) just brought it up but DNS may not have
# settled in the host network namespace yet.
for i in $(seq 1 30); do
    if docker exec -e PGPASSWORD="${PROXY_ADMIN_PASS}" \
        "$(docker ps --filter "name=proxysql.${INFRA_ID}" --format '{{.Names}}' | head -1)" \
        psql -X -h"${PROXY_HOST}" -p"${PROXY_ADMIN_PORT}" -U"${PROXY_ADMIN_USER}" -c "select 1;" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

PROXY_CTNR="$(docker ps --filter "name=proxysql.${INFRA_ID}" --format '{{.Names}}' | head -1)"
if [ -z "${PROXY_CTNR}" ]; then
    echo "ERROR: ProxySQL container for INFRA_ID=${INFRA_ID} not running"
    exit 1
fi

# Replace the default TCP-based pgsql_servers with socket-based ones.
# Same hostgroups (0/1) and same comment so the rest of the suite sees
# an identical-looking pgsql_servers table; the only difference is the
# hostname/port pair, which is exactly what this test exercises.
docker exec -i -e PGPASSWORD="${PROXY_ADMIN_PASS}" "${PROXY_CTNR}" \
    psql -X -h"${PROXY_HOST}" -p"${PROXY_ADMIN_PORT}" -U"${PROXY_ADMIN_USER}" <<'SQL'
DELETE FROM pgsql_servers;
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
    VALUES (0, '/var/run/postgresql-shared', 0, 0, 50, 'pgsql1-unix-socket'),
           (1, '/var/run/postgresql-shared', 0, 0, 50, 'pgsql1-unix-socket');
LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
SQL

echo ">>> [pgsql-socket/setup-infras] Switched pgsql_servers to Unix-socket mode"
