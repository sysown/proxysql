#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "${SCRIPT_DIR}/.env"
CONTAINER="infra-mysql-router-ic-${INFRA_ID}-dbdeployer1-1"

for port in 3306 3307 3308 3309; do
    docker exec "${CONTAINER}" mysql -hdbdeployer1.infra-mysql-router-ic -P"${port}" \
        -uroot -p"${ROOT_PASSWORD}" -NBe 'SELECT @@server_uuid' >/dev/null
done
docker exec "${CONTAINER}" mysqlsh --version | grep -Eq 'Ver 8\.[4-9]\.'
