#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env

CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"

# NOTE: Do NOT delete/recreate cert bundles here.
# The MySQL docker-mysql-post.bash (which runs first) already collected the
# backend's CA cert into dbservers-cert-bundle.pem. MariaDB doesn't generate
# SSL certs in the sandbox datadir, so deleting the bundle would remove the
# MySQL certs without replacing them, breaking SSL tests.

# Verify all 3 MySQL nodes are reachable
for PORT in 3306 3307 3308; do
    echo -n "Verifying MySQL on ${CONTAINER}:${PORT}..."
    MAX_WAIT=60
    COUNT=0
    while ! docker exec "${CONTAINER}" mysql -h127.0.0.1 -P${PORT} -uroot -p"${ROOT_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " TIMEOUT"
            exit 1
        fi
        echo -n "."
        sleep 2
        COUNT=$((COUNT + 2))
    done
    echo " OK"
done

# Verify replication is working on nodes 2 and 3
for PORT in 3307 3308; do
    echo -n "Checking replication on port ${PORT}..."
    SLAVE_STATUS=$(docker exec "${CONTAINER}" mysql -h127.0.0.1 -P${PORT} -uroot -p"${ROOT_PASSWORD}" -E -e "SHOW SLAVE STATUS" 2>/dev/null)
    IO_RUNNING=$(echo "${SLAVE_STATUS}" | grep "Slave_IO_Running:" | awk '{print $2}')
    SQL_RUNNING=$(echo "${SLAVE_STATUS}" | grep "Slave_SQL_Running:" | awk '{print $2}')
    if [ "${IO_RUNNING}" = "Yes" ] && [ "${SQL_RUNNING}" = "Yes" ]; then
        echo " OK (IO: Yes, SQL: Yes)"
    else
        echo " WARNING (IO: ${IO_RUNNING}, SQL: ${SQL_RUNNING})"
    fi
done

echo "docker-mysql-post.bash complete."
