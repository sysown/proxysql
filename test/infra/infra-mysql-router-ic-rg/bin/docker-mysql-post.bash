#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
. "${SCRIPT_DIR}/.env"
CONTAINER="infra-mysql-router-ic-rg-${INFRA_ID}-dbdeployer1-1"

for port in 3306 3307 3308 3309; do
	docker exec -e MYSQL_PWD="${ROOT_PASSWORD}" "${CONTAINER}" mysql \
		-hdbdeployer1.infra-mysql-router-ic-rg -P"${port}" -uroot \
		-NBe 'SELECT @@server_uuid' >/dev/null
done
# Routing Guidelines need MySQL Shell >= 9.2 (metadata schema 2.3+).
docker exec "${CONTAINER}" mysqlsh --version | grep -Eq 'Ver 9\.([2-9]|[1-9][0-9])\.'
for attempt in $(seq 1 30); do
	if docker exec "${CONTAINER}" test -f /var/lib/mysqlsh-queue/.server-ready; then
		exit 0
	fi
	sleep 1
done
echo "ERROR: MySQL Shell request queue did not start" >&2
exit 1
