#!/bin/bash
set -e
set -o pipefail

[ -f .env ] && . .env

BUNDLE_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
CONTAINER="${COMPOSE_PROJECT}-mysql1-1"

sudo mkdir -p "${BUNDLE_DIR}"
sudo chmod 777 "${BUNDLE_DIR}"

DB_BUNDLE="${BUNDLE_DIR}/dbservers-cert-bundle.pem"
CA_BUNDLE="${BUNDLE_DIR}/caservers-cert-bundle.pem"
sudo rm -f "${DB_BUNDLE}" "${CA_BUNDLE}"

echo -n "Waiting for container '${CONTAINER}' ..."
MAX_WAIT=120
COUNT=0
while true; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT"
        docker logs "${CONTAINER}" | tail -n 20
        exit 1
    fi
    STATE=$(docker inspect -f '{{.State.Running}}' "${CONTAINER}" 2>/dev/null || echo "false")
    if [ "${STATE}" != "true" ]; then
        echo -e "\nERROR: Container ${CONTAINER} is NOT running!"
        docker logs "${CONTAINER}" | tail -n 20
        exit 1
    fi
    if docker exec "${CONTAINER}" mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; then
        echo " OK"
        break
    fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT + 2))
done

echo "Configuring users on ${CONTAINER}..."
docker exec -i "${CONTAINER}" mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" <<SQL
SET SQL_LOG_BIN=0;

DELETE FROM mysql.user WHERE User='';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY '${ROOT_PASSWORD}' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}' WITH GRANT OPTION;
GRANT USAGE ON *.* TO 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' IDENTIFIED BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%' IDENTIFIED BY 'testuser';
-- MySQL 5.6 limits usernames to 16 chars, so '${INFRA}' is documented here but intentionally disabled.
-- GRANT ALL PRIVILEGES ON \`%test%\`.* TO '${INFRA}'@'%' IDENTIFIED BY '${INFRA}';
GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%' IDENTIFIED BY 'ssluser' REQUIRE SSL;

CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;

GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest1'@'%' IDENTIFIED BY 'sbtest1';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest1'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest1'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest1'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest2'@'%' IDENTIFIED BY 'sbtest2';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest2'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest2'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest2'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest3'@'%' IDENTIFIED BY 'sbtest3';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest3'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest3'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest3'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest4'@'%' IDENTIFIED BY 'sbtest4';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest4'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest4'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest4'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest7'@'%' IDENTIFIED BY 'sbtest7';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest8'@'%' IDENTIFIED BY 'sbtest8';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest8'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest8'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest8'@'%';

FLUSH PRIVILEGES;
SQL

if docker exec "${CONTAINER}" test -f /var/lib/mysql/ca.pem; then
    echo "Collecting CA from ${CONTAINER}..."
    docker cp "${CONTAINER}:/var/lib/mysql/ca.pem" - | tar -Ox | sudo tee -a "${DB_BUNDLE}" | sudo tee -a "${CA_BUNDLE}" >/dev/null
    sudo chmod 666 "${DB_BUNDLE}" "${CA_BUNDLE}"
else
    echo ">>> CA not found on ${CONTAINER}. Skipping collection."
fi
