#!/bin/bash
# Configure ProxySQL for the infra-dbdeployer-pgsql17-repl backend (automatic
# rw-split via Toxiproxy + monitor-driven pg_is_in_recovery() demotion).
#
# Follows the infra-pgsql17-repl pattern: eval-expand the SQL template (so
# ${INFRA_ID}/${WHG}/${RHG}/${ROOT_PASSWORD} are substituted) and pipe it into
# the ProxySQL admin interface over the PG protocol (port 6132), NOT the MySQL
# admin protocol -- ProxySQL's pgsql_* admin tables are only writable there.
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

# ROOT_PASSWORD is normally exported by the caller (docker-compose-init.bash /
# start-proxysql-isolated.bash), but ensure-infras.bash's "already running"
# reconfigure path invokes this script directly without it. Re-derive it with
# the same deterministic formula so the 'postgres' pgsql_users row keeps
# matching the password the entrypoint actually set on the role.
ROOT_PASSWORD="${ROOT_PASSWORD:-$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for PGSQL Replication (automatic rw-split via Toxiproxy): ${INFRA}"

# Wait for ProxySQL admin (MySQL protocol, port 6032) to be reachable.
while ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; do
    echo -n '.'
    sleep 1
done

# Pre-process the SQL template.
SQL_TEMPLATE=$(cat ./conf/proxysql/infra-config.sql)
SQL_CONTENT=$(eval "echo \"${SQL_TEMPLATE}\"")

# Apply configuration via docker exec using psql (ProxySQL Admin supports PG protocol on port 6132).
echo "${SQL_CONTENT}" | docker exec -i "${PROXY_CONTAINER}" env PGPASSWORD='admin' psql -h127.0.0.1 -p6132 -Uadmin -dadmin
