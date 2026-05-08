#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

INFRA_SQL_PATH="${SCRIPT_DIR}/../conf/proxysql/infra-config.sql"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for Cluster: ${INFRA}"

docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
$(eval "echo \"$(cat "${INFRA_SQL_PATH}")\"")

-- Clean up existing user records
DELETE FROM mysql_users WHERE username='root';
DELETE FROM mysql_users WHERE username='testuser';

-- Register root user (fast_forward=0 by default)
INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, fast_forward, backend, frontend, comment)
VALUES ('root', '${ROOT_PASSWORD}', 1, ${WHG}, 0, 1, 1, 'dynamic-root-user');

-- Register testuser (fast_forward=0 by default)
INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, fast_forward, backend, frontend, comment)
VALUES ('testuser', 'testuser', 1, ${WHG}, 0, 1, 1, 'universal-testuser');

-- Ensure cluster specific user is also correctly set
DELETE FROM mysql_users WHERE username='${INFRA}';
INSERT OR IGNORE INTO mysql_users (username, password, active, default_hostgroup, fast_forward, backend, frontend, comment)
VALUES ('${INFRA}', '${INFRA}', 1, ${WHG}, 0, 1, 1, '${INFRA}');

-- Synchronize monitor credentials
UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_username';
UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_password';

LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;
LOAD MYSQL VARIABLES TO RUNTIME;
-- Ensure hostgroup 0 and 1 exist if not already present
INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
SELECT 0, hostname, port, max_replication_lag, max_connections, 'fallback-hg0'
FROM mysql_servers WHERE hostgroup_id = ${WHG} AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id = 0);

INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_replication_lag, max_connections, comment)
SELECT 1, hostname, port, max_replication_lag, max_connections, 'fallback-hg1'
FROM mysql_servers WHERE hostgroup_id = ${RHG} AND NOT EXISTS (SELECT 1 FROM mysql_servers WHERE hostgroup_id = 1);

-- Ensure galera hostgroup 0/1 mapping exists
INSERT INTO mysql_galera_hostgroups (writer_hostgroup, backup_writer_hostgroup, reader_hostgroup, offline_hostgroup, active, max_writers, writer_is_also_reader, max_transactions_behind, comment)
SELECT 0, 2, 1, 3, 1, 1, 1, 0, 'fallback-galera-hg'
WHERE NOT EXISTS (SELECT 1 FROM mysql_galera_hostgroups WHERE writer_hostgroup = 0);

LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
SAVE MYSQL VARIABLES TO DISK;
SQL

if [ $? -eq 0 ]; then echo "Cluster ${INFRA} registered in ProxySQL."; else echo "ERROR: ProxySQL configuration FAILED for ${INFRA}"; exit 1; fi
