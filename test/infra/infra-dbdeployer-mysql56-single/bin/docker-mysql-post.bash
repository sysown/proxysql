#!/bin/bash
set -e
set -o pipefail

[ -f .env ] && . .env

CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"
BUNDLE_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"

sudo mkdir -p "${BUNDLE_DIR}"
sudo chmod 777 "${BUNDLE_DIR}"

DB_BUNDLE="${BUNDLE_DIR}/dbservers-cert-bundle.pem"
CA_BUNDLE="${BUNDLE_DIR}/caservers-cert-bundle.pem"
sudo rm -f "${DB_BUNDLE}" "${CA_BUNDLE}"

echo -n "Verifying MySQL on ${CONTAINER}:3306..."
MAX_WAIT=60
COUNT=0
while ! docker exec "${CONTAINER}" mysql -h127.0.0.1 -P3306 -uroot -p"${ROOT_PASSWORD}" -e "SELECT 1" >/dev/null 2>&1; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT"
        exit 1
    fi
    echo -n "."
    sleep 2
    COUNT=$((COUNT + 2))
done
echo " OK"

SANDBOX_DATA_DIR=$(docker exec "${CONTAINER}" bash -lc "ls -d /root/sandboxes/msb_*/data 2>/dev/null | head -1")
if [ -n "${SANDBOX_DATA_DIR}" ] && docker exec "${CONTAINER}" test -f "${SANDBOX_DATA_DIR}/ca.pem"; then
    echo "Collecting CA cert from ${SANDBOX_DATA_DIR}..."
    docker exec "${CONTAINER}" cat "${SANDBOX_DATA_DIR}/ca.pem" | sudo tee -a "${DB_BUNDLE}" | sudo tee -a "${CA_BUNDLE}" >/dev/null
    sudo chmod 666 "${DB_BUNDLE}" "${CA_BUNDLE}"
else
    echo ">>> CA cert not found in sandbox data directory. Skipping bundle collection."
fi

echo "docker-mysql-post.bash complete."
