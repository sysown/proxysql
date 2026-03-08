#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env
PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for Clickhouse: ${INFRA}"

while ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; do
    echo -n '.'
    sleep 1
done

SQL_TEMPLATE=$(cat ./conf/proxysql/infra-config.sql)
SQL_CONTENT=$(eval "echo \"${SQL_TEMPLATE}\"")

docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
${SQL_CONTENT}
LOAD CLICKHOUSE SERVERS TO RUNTIME;
SAVE CLICKHOUSE SERVERS TO DISK;
SQL
