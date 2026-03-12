#!/bin/bash
set -e
set -o pipefail
[ -f .env ] && . .env

BUNDLE_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
sudo mkdir -p "${BUNDLE_DIR}"
sudo chmod 777 "${BUNDLE_DIR}"

DB_BUNDLE="${BUNDLE_DIR}/dbservers-cert-bundle.pem"
CA_BUNDLE="${BUNDLE_DIR}/caservers-cert-bundle.pem"
sudo rm -f "${DB_BUNDLE}" "${CA_BUNDLE}"

for i in 1 2 3; do
    SERVICE="mysql$i"
    CONTAINER="${COMPOSE_PROJECT}-${SERVICE}-1"
    echo -n "Waiting for container '${CONTAINER}' ..."
    
    MAX_WAIT=120
    COUNT=0
    PASS_OPT=""
    MAX_WAIT=120
    COUNT=0
    while true; do
        if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; docker logs "${CONTAINER}" | tail -n 20; exit 1; fi
        STATE=$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || echo "false")
        if [ "${STATE}" != "true" ]; then echo -e "\nERROR: Container ${CONTAINER} is NOT running!"; docker logs "${CONTAINER}" | tail -n 20; exit 1; fi
        if docker exec "${CONTAINER}" mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; then PASS_OPT="-p${ROOT_PASSWORD}"; echo " OK (Auth: Dynamic)."; break; fi
        if docker exec "${CONTAINER}" mysql -h127.0.0.1 -uroot -e "SELECT 1" >/dev/null 2>&1; then PASS_OPT=""; echo " OK (Auth: Empty)."; break; fi
        echo -n "."; sleep 2; COUNT=$((COUNT+2))
    done

    echo "Configuring users on ${CONTAINER}..."
    docker exec -i "${CONTAINER}" mysql -h127.0.0.1 -uroot ${PASS_OPT} <<SQL || { echo "ERROR: Failed user provisioning on ${CONTAINER}"; exit 1; }
SET SQL_LOG_BIN=0;

-- Ensure root user has the correct dynamic password and plugin
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
-- Also fix the local root user just in case
ALTER USER 'root'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- testuser
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- Cluster specific user
CREATE USER IF NOT EXISTS '${INFRA}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${INFRA}';
GRANT ALL PRIVILEGES ON *.* TO '${INFRA}'@'%';

-- granular sbtest users
CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;
$(for j in $(seq 1 10); do 
    echo "CREATE USER IF NOT EXISTS 'sbtest${j}'@'%' IDENTIFIED BY 'sbtest${j}';"
    for db in sysbench test t1 jdbc_test; do
        echo "GRANT ALL PRIVILEGES ON ${db}.* TO 'sbtest${j}'@'%';"
    done
done)

    FLUSH PRIVILEGES;
SQL

    if [ "$i" -gt 1 ]; then
        echo "Setting up replication on ${CONTAINER} (Source: mysql1)..."
        docker exec -i "${CONTAINER}" mysql -h127.0.0.1 -uroot ${PASS_OPT} <<SQL || { echo "ERROR: Failed replication setup on ${CONTAINER}"; exit 1; }
STOP REPLICA;
CHANGE REPLICATION SOURCE TO SOURCE_HOST='mysql1.${INFRA}', SOURCE_USER='root', SOURCE_PASSWORD='${ROOT_PASSWORD}', SOURCE_AUTO_POSITION=1;
START REPLICA;
SQL
    fi

    if docker exec "${CONTAINER}" test -f /var/lib/mysql/ca.pem; then echo "Collecting CA from ${CONTAINER}...";

    docker cp "${CONTAINER}:/var/lib/mysql/ca.pem" - | tar -Ox | sudo tee -a "${DB_BUNDLE}" | sudo tee -a "${CA_BUNDLE}" > /dev/null; else echo ">>> CA not found on ${CONTAINER}. Skipping collection."; fi
done
[ -f "${DB_BUNDLE}" ] && sudo chmod 666 "${DB_BUNDLE}" "${CA_BUNDLE}" || true
