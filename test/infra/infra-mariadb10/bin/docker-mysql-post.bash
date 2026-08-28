#!/bin/bash
set -e
set -o pipefail

[ -f .env ] && . .env

if [ -z "${ROOT_PASSWORD}" ]; then
    echo "Error: ROOT_PASSWORD is not set."
    exit 1
fi

for i in 1 2 3; do
    SERVICE="mariadb$i"
    CONTAINER="${COMPOSE_PROJECT}-${SERVICE}-1"
    
    echo -n "Waiting for '${CONTAINER}' ..."
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

    echo -n "Configuring '${CONTAINER}' ..."
    docker exec -i "${CONTAINER}" mysql -uroot ${PASS_OPT} <<SQL || { echo "ERROR: Failed user provisioning on ${CONTAINER}"; exit 1; }
-- Ensure root user has the correct dynamic password
-- For MariaDB 10.x, we use standard password setting
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
SET PASSWORD FOR 'root'@'%' = PASSWORD('${ROOT_PASSWORD}');
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${ROOT_PASSWORD}');
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

CREATE USER IF NOT EXISTS rpl_user@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO rpl_user@'%';
CREATE USER IF NOT EXISTS mariadbuser@'%' IDENTIFIED BY 'mariadbuser';
CREATE USER IF NOT EXISTS mariadbuserff@'%' IDENTIFIED BY 'mariadbuserff';
CREATE USER IF NOT EXISTS monitor@'%' IDENTIFIED BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO monitor@'%';
-- Compatibility users
CREATE USER IF NOT EXISTS testuser@'%' IDENTIFIED BY 'testuser';
GRANT ALL PRIVILEGES ON \`%test%\`.* TO testuser@'%';
FLUSH PRIVILEGES;
SQL
    echo ' done.'

    if [ "$i" -gt 1 ]; then
        echo -n "Setting up replication on ${CONTAINER} (Source: mariadb1.${INFRA}) ..."
        docker exec -i "${CONTAINER}" mysql -uroot -p"${ROOT_PASSWORD}" <<SQL || { echo "ERROR: Failed replication setup on ${CONTAINER}"; exit 1; }
STOP SLAVE;
CHANGE MASTER TO MASTER_HOST='mariadb1.${INFRA}', MASTER_USER='root', MASTER_PASSWORD='${ROOT_PASSWORD}';
START SLAVE;
SQL
        echo ' done.'
    fi
done

true
