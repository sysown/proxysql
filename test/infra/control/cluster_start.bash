#!/bin/bash
set -e
set -o pipefail

# SUDO helper: empty if root
SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

# TAP diag helper
diag() {
    echo "$@"
}

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID is not set."; exit 1; fi

NETWORK_NAME="${INFRA_ID}_backend"
CLUSTER_CONFIG="${SCRIPT_DIR}/proxysql-cluster-node.cnf"
NUM_NODES=${PROXYSQL_CLUSTER_NODES:-9}

if [[ "${SKIP_CLUSTER_START}" == "1" ]] || [[ "${SKIP_CLUSTER_START}" == "true" ]] || [[ "${NUM_NODES}" == "0" ]]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Cluster start SKIPPED (SKIP_CLUSTER_START=${SKIP_CLUSTER_START}, Nodes=${NUM_NODES})"
    exit 0
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Cluster check/start (Nodes: ${NUM_NODES}) ..."

if command -v docker &> /dev/null; then
    # Ensure network exists
    docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1 || docker network create "${NETWORK_NAME}"

    for i in $(seq 1 "${NUM_NODES}"); do
        NODE_NAME="proxy-node${i}"
        CONTAINER_NAME="${NODE_NAME}.${INFRA_ID}"
        NODE_DIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/${NODE_NAME}"
        
        if [ ! "$(docker ps -q -f name=${CONTAINER_NAME})" ]; then
            echo ">>> Starting Node: ${CONTAINER_NAME}"
            $SUDO mkdir -p "${NODE_DIR}"
            $SUDO chmod -R 777 "${NODE_DIR}"
            docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
            
            if ! docker run -d                 --name "${CONTAINER_NAME}"                 --hostname "${NODE_NAME}"                 --network "${NETWORK_NAME}"                 --network-alias "${NODE_NAME}"                 -v "${WORKSPACE}/src/proxysql:/usr/bin/proxysql"                 -v "${CLUSTER_CONFIG}:/etc/proxysql.cnf"                 -v "${NODE_DIR}:/var/lib/proxysql"                 proxysql-ci-base:latest                 /bin/bash -c "/usr/bin/proxysql --idle-threads --clickhouse-server --sqlite3-server -f -c /etc/proxysql.cnf -D /var/lib/proxysql 2>&1 | tee /var/lib/proxysql/proxysql.log"; then
                echo "ERROR: Failed to start container ${CONTAINER_NAME}"
                exit 1
            fi
        fi
    done
fi

for i in $(seq 1 "${NUM_NODES}"); do
    NODE_NAME="proxy-node${i}"
    CONTAINER_NAME="${NODE_NAME}.${INFRA_ID}"
    echo -n "Waiting for ${NODE_NAME} ..."
    
    MAX_WAIT=30
    COUNT=0
    while [ $COUNT -lt $MAX_WAIT ]; do
        if command -v docker &> /dev/null; then
            if docker exec "${CONTAINER_NAME}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; then
                echo " OK."
                break
            fi
        else
            if mysql -uadmin -padmin -h "${NODE_NAME}" -P 6032 -e 'SELECT 1' >/dev/null 2>&1; then
                echo " OK."
                break
            fi
        fi

        echo -n '.'
        sleep 1
        COUNT=$((COUNT+1))
    done
    if [ $COUNT -ge $MAX_WAIT ]; then 
        echo " TIMEOUT"
        if command -v docker &> /dev/null; then docker logs "${CONTAINER_NAME}" | tail -n 5; fi
        exit 1 
    fi
done

echo ">>> ProxySQL Cluster is UP."
