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

# Wait for ProxySQL admin (MySQL protocol, port 6032) to be reachable. Bounded:
# docker-compose-init.bash re-execs itself under `timeout`, but ensure-infras.bash's
# reconfigure path calls this script directly, where an unbounded loop would hang
# the run instead of failing it.
PROXY_WAIT_SECONDS="${PROXY_WAIT_SECONDS:-120}"
waited=0
while ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; do
    if [ "${waited}" -ge "${PROXY_WAIT_SECONDS}" ]; then
        echo " TIMEOUT"
        echo "ERROR: ProxySQL admin on ${PROXY_CONTAINER} not reachable after ${PROXY_WAIT_SECONDS}s."
        echo ">>> Container Logs:"
        docker logs "${PROXY_CONTAINER}" 2>&1 | tail -n 50
        exit 1
    fi
    echo -n '.'
    sleep 1
    waited=$((waited + 1))
done

# Pre-process the SQL template. envsubst substitutes exactly the five variables
# named below and leaves every other '$' alone; the previous eval-echo form ran
# the template through the shell, so any quote, backtick or $(...) that a future
# edit introduced into the SQL would be mangled or executed. envsubst reads only
# EXPORTED variables, hence the explicit export of the .env-sourced WHG/RHG.
export INFRA_ID INFRA WHG RHG ROOT_PASSWORD
SQL_CONTENT=$(envsubst '${INFRA_ID} ${INFRA} ${WHG} ${RHG} ${ROOT_PASSWORD}' \
    < "${SCRIPT_DIR}/../conf/proxysql/infra-config.sql")

# Apply configuration via docker exec using psql (ProxySQL Admin supports PG
# protocol on port 6132). ON_ERROR_STOP=1 makes psql abort with a non-zero
# exit on the FIRST SQL-level error (bad token, constraint violation, ...);
# without it psql prints the error, keeps going, and exits 0 -- silently
# defeating set -e and this script's fail-non-zero contract.
echo "${SQL_CONTENT}" | docker exec -i "${PROXY_CONTAINER}" env PGPASSWORD='admin' psql -v ON_ERROR_STOP=1 -h127.0.0.1 -p6132 -Uadmin -dadmin
