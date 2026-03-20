#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for MariaDB Cluster: ${INFRA}"

# Wait for ProxySQL to be ready
echo -n "Waiting for '${PROXY_CONTAINER}' Admin interface ..."
while ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; do
    echo -n '.'
    sleep 1
done
echo " ready."

# Pre-process the SQL template
SQL_TEMPLATE=$(cat ./conf/proxysql/infra-config.sql)
SQL_CONTENT=$(eval "echo \"${SQL_TEMPLATE}\"")

docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
${SQL_CONTENT}

-- Ensure hostgroup 0 and 1 exist if not already present, pointing to MariaDB
INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
SELECT 0, hostname, port, max_replication_lag, max_connections, 'fallback-hg0'
FROM mysql_servers WHERE hostgroup_id = ${WHG} AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id = 0);

INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
SELECT 1, hostname, port, max_replication_lag, max_connections, 'fallback-hg1'
FROM mysql_servers WHERE hostgroup_id = ${RHG} AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id = 1);

-- Ensure replication hostgroup 0/1 mapping exists
INSERT INTO mysql_replication_hostgroups (writer_hostgroup, reader_hostgroup, comment)
SELECT 0, 1, 'fallback-repl-hg'
WHERE NOT EXISTS (SELECT 1 FROM mysql_replication_hostgroups WHERE writer_hostgroup = 0 AND reader_hostgroup = 1);

LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SQL

if [ $? -eq 0 ]; then echo "MariaDB Cluster ${INFRA} registered in ProxySQL."; else echo "ERROR: ProxySQL configuration FAILED for ${INFRA}"; exit 1; fi
