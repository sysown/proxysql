#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"

PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for Cluster: ${INFRA}"

docker exec -i "${PROXY_CONTAINER}" mysql -uradmin -pradmin -h127.0.0.1 -P6032 <<SQL
$(eval "echo \"$(cat ./conf/proxysql/infra-config.sql)\"")

-- Additional configuration for binlog tests
-- Ensure monitor credentials are synchronized
UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_username';
UPDATE global_variables SET variable_value='monitor' WHERE variable_name='mysql-monitor_password';

LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
SQL

if [ $? -eq 0 ]; then echo "Cluster ${INFRA} registered in ProxySQL."; else echo "ERROR: ProxySQL configuration FAILED for ${INFRA}"; exit 1; fi
