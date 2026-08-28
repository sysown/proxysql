#!/bin/bash
set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for Cluster: ${INFRA}"

SQL_TEMPLATE=$(cat ./conf/proxysql/infra-config.sql)
SQL_CONTENT=$(eval "echo \"${SQL_TEMPLATE}\"")

docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
${SQL_CONTENT}
SQL

if [ $? -eq 0 ]; then echo "Cluster ${INFRA} registered in ProxySQL."; else echo "ERROR: ProxySQL configuration FAILED for ${INFRA}"; exit 1; fi
