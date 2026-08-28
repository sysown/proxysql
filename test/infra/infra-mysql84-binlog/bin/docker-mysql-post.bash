#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env

for i in 1 2 3; do
    SERVICE="mysql$i"
    CONTAINER="${COMPOSE_PROJECT}-${SERVICE}-1"
    echo -n "Waiting for container '${CONTAINER}' ..."

    MAX_WAIT=120
    COUNT=0
    PASS_OPT=""
    while true; do
        if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; docker logs "${CONTAINER}" | tail -n 20; exit 1; fi
        STATE=$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || echo "false")
        if [ "${STATE}" != "true" ]; then echo -e "\nERROR: Container ${CONTAINER} is NOT running!"; docker logs "${CONTAINER}" | tail -n 20; exit 1; fi
        # Try dynamic password first
        if docker exec "${CONTAINER}" mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; then
            PASS_OPT="-p${ROOT_PASSWORD}"
            echo " OK (Auth: Dynamic)."
            break
        fi
        # Try default root password from image
        if docker exec "${CONTAINER}" mysql -h127.0.0.1 -uroot -proot -e "SELECT 1" >/dev/null 2>&1; then
            PASS_OPT="-proot"
            echo " OK (Auth: Default root)."
            break
        fi
        # Try empty password
        if docker exec "${CONTAINER}" mysql -h127.0.0.1 -uroot -e "SELECT 1" >/dev/null 2>&1; then
            PASS_OPT=""
            echo " OK (Auth: Empty)."
            break
        fi
        echo -n "."; sleep 2; COUNT=$((COUNT+2))
    done

    if [ "$i" -eq 1 ]; then
        echo "Configuring master (mysql1)..."
        docker exec -i "${CONTAINER}" mysql -h127.0.0.1 -uroot ${PASS_OPT} <<SQL || { echo "ERROR: Failed master configuration on ${CONTAINER}"; exit 1; }
SET GLOBAL READ_ONLY=0;

-- Ensure root user has the correct dynamic password (replicated to replicas)
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user (replicated to replicas)
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- testuser (replicated to replicas)
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- Binlog user (required for binlog reader, replicated to replicas)
CREATE USER IF NOT EXISTS 'binlog'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'binlog';
GRANT USAGE, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'binlog'@'%';

-- sbtest7 and sbtest8 users (specifically for binlog tests, replicated to replicas)
CREATE USER IF NOT EXISTS 'sbtest7'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'sbtest7';
GRANT ALL PRIVILEGES ON *.* TO 'sbtest7'@'%';
CREATE USER IF NOT EXISTS 'sbtest8'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'sbtest8';
GRANT ALL PRIVILEGES ON *.* TO 'sbtest8'@'%';

-- Create test databases
CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest8'@'%';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest8'@'%';

FLUSH PRIVILEGES;
SQL
    else
        echo "Configuring replica (mysql${i})..."
        docker exec -i "${CONTAINER}" mysql -h127.0.0.1 -uroot ${PASS_OPT} <<SQL || { echo "ERROR: Failed replica configuration on ${CONTAINER}"; exit 1; }
SET GLOBAL READ_ONLY=1;
RESET BINARY LOGS AND GTIDS;

-- Configure replication using MySQL 8.4 syntax
CHANGE REPLICATION SOURCE TO SOURCE_HOST='mysql1.${INFRA}', SOURCE_USER='root', SOURCE_PASSWORD='${ROOT_PASSWORD}', SOURCE_AUTO_POSITION=1;
START REPLICA;

FLUSH PRIVILEGES;
SQL
    fi
done

echo "================================================================================"
echo "MySQL cluster configuration complete."
echo "================================================================================"
