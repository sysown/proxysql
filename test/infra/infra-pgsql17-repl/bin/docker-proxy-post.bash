#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for PGSQL Replication: ${INFRA}"

# Wait for ProxySQL
while ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; do
    echo -n '.'
    sleep 1
done

# Pre-process the SQL template
SQL_TEMPLATE=$(cat ./conf/proxysql/infra-config.sql)
SQL_CONTENT=$(eval "echo \"${SQL_TEMPLATE}\"")

# Apply configuration via docker exec using psql (ProxySQL Admin supports PG protocol on port 6132)
echo "${SQL_CONTENT}" | docker exec -i "${PROXY_CONTAINER}" env PGPASSWORD='admin' psql -h127.0.0.1 -p6132 -Uadmin -dadmin
