#!/bin/bash
set -e
set -o pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${SCRIPT_DIR}/../.env" ] && . "${SCRIPT_DIR}/../.env"

CONTAINER="${COMPOSE_PROJECT}-dbdeployer1-1"

# Prepare cert bundle directories
BUNDLE_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
sudo mkdir -p "${BUNDLE_DIR}"
sudo chmod 777 "${BUNDLE_DIR}"

DB_BUNDLE="${BUNDLE_DIR}/dbservers-cert-bundle.pem"
CA_BUNDLE="${BUNDLE_DIR}/caservers-cert-bundle.pem"
sudo rm -f "${DB_BUNDLE}" "${CA_BUNDLE}"

# Verify all 3 MariaDB nodes are reachable
for PORT in 3306 3307 3308; do
    echo -n "Verifying MariaDB on ${CONTAINER}:${PORT}..."
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

# Verify Galera cluster status
echo -n "Checking Galera cluster status..."
CLUSTER_SIZE=$(docker exec "${CONTAINER}" mysql -h127.0.0.1 -P3306 -uroot -p"${ROOT_PASSWORD}" --batch -N -e \
    "SELECT Variable_value FROM information_schema.global_status WHERE Variable_name='wsrep_cluster_size'" 2>/dev/null)
if [ "$CLUSTER_SIZE" = "3" ]; then
    echo " OK (cluster size 3)"
else
    echo " FAILED (cluster size $CLUSTER_SIZE)"
    exit 1
fi

# Collect SSL CA certs from ALL nodes
for NODE_DIR in node1 node2 node3; do
    DATADIR=$(docker exec "${CONTAINER}" bash -c "ls -d /root/sandboxes/galera_msb_*/${NODE_DIR}/data" 2>/dev/null)
    if [ -n "${DATADIR}" ]; then
        if docker exec "${CONTAINER}" test -f "${DATADIR}/ca.pem"; then
            echo "Collecting CA cert from ${NODE_DIR}..."
            docker exec "${CONTAINER}" cat "${DATADIR}/ca.pem" | sudo tee -a "${DB_BUNDLE}" | sudo tee -a "${CA_BUNDLE}" > /dev/null
        else
            echo ">>> CA cert not found at ${DATADIR}/ca.pem. Skipping ${NODE_DIR}."
        fi
    fi
done
[ -f "${DB_BUNDLE}" ] && sudo chmod 666 "${DB_BUNDLE}" "${CA_BUNDLE}" || true

echo "docker-mysql-post.bash complete."
