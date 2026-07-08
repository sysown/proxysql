#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"
# INFRA_ID is global
PROXY_CONTAINER="proxysql.${INFRA_ID}"

echo ">>> Configuring ProxySQL (${PROXY_CONTAINER}) for ClickHouse"

# Wait for ProxySQL Admin
echo -n "Waiting for ProxySQL Admin..."
MAX_WAIT=30
COUNT=0
while ! docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "SELECT 1" >/dev/null 2>&1; do
    echo -n "."
    sleep 1
    COUNT=$((COUNT+1))
    if [ $COUNT -gt $MAX_WAIT ]; then echo " FAILED"; exit 1; fi
done
echo " OK."

# Apply configuration
docker exec -i "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
$(eval "echo \"$(cat ./conf/proxysql/infra-config.sql)\"")
SQL

echo "ClickHouse registered in ProxySQL."
