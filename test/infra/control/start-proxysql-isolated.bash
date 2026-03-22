#!/bin/bash
set -e
set -o pipefail

# SUDO helper: empty if root
SUDO=""
if [ "$(id -u)" != "0" ]; then SUDO="sudo"; fi

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

if [ -z "${INFRA_ID}" ]; then echo "Error: INFRA_ID is not set."; exit 1; fi

export ROOT_PASSWORD=$(echo -n "${INFRA_ID}" | sha256sum | head -c 10)

NETWORK_NAME="${INFRA_ID}_backend"
PROXY_CONTAINER="proxysql.${INFRA_ID}"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
PROXY_DATA_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/proxysql"
GENERIC_CONFIG="${SCRIPT_DIR}/proxysql-ci.cnf"

# Coverage data directory (separate per INFRA_ID to avoid parallel write conflicts)
# GCOV_PREFIX redirects .gcda files to a separate directory for each ProxySQL instance
COVERAGE_DATA_DIR="${INFRA_LOGS_PATH}/${INFRA_ID}/gcov"
mkdir -p "${COVERAGE_DATA_DIR}"

echo ">>> Setting up isolated network: ${NETWORK_NAME}"
docker network inspect ${NETWORK_NAME} >/dev/null 2>&1 || docker network create ${NETWORK_NAME}

echo ">>> Preparing ProxySQL data directory: ${PROXY_DATA_DIR}"
$SUDO mkdir -p "${PROXY_DATA_DIR}"
$SUDO chmod -R 777 "${INFRA_LOGS_PATH}/${INFRA_ID}"
$SUDO rm -f "${PROXY_DATA_DIR}/proxysql.db" "${PROXY_DATA_DIR}"/*.pem

docker rm -f "${PROXY_CONTAINER}" >/dev/null 2>&1 || true

echo ">>> Starting ProxySQL container: ${PROXY_CONTAINER}"
docker run -d     --name "${PROXY_CONTAINER}"     --hostname "proxysql"     --network "${NETWORK_NAME}"     --network-alias "proxysql"     -v "${WORKSPACE}/src/proxysql:/usr/bin/proxysql"     -v "${GENERIC_CONFIG}:/etc/proxysql.cnf"     -v "${PROXY_DATA_DIR}:/var/lib/proxysql"     -v "${COVERAGE_DATA_DIR}:/gcov"     -e GCOV_PREFIX="/gcov"     -e GCOV_PREFIX_STRIP="3"     proxysql-ci-base:latest     /bin/bash -c "/usr/bin/proxysql --idle-threads --clickhouse-server --sqlite3-server -f -c /etc/proxysql.cnf -D /var/lib/proxysql 2>&1 | tee /var/lib/proxysql/proxysql.log"

if [ -f /.dockerenv ]; then
    RUNNER_ID=$(hostname)
    docker network connect "${NETWORK_NAME}" "${RUNNER_ID}" || true
fi

echo -n "Waiting for ${PROXY_CONTAINER}:6032 "
MAX_WAIT=30
COUNT=0
while [ $COUNT -lt $MAX_WAIT ]; do
    if docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e 'SELECT 1' >/dev/null 2>&1; then
        # Provision clickhouse interface if needed
        docker exec "${PROXY_CONTAINER}" mysql -uadmin -padmin -h127.0.0.1 -P6032 -e "
            SET clickhouse-mysql_ifaces='0.0.0.0:8000';
            LOAD CLICKHOUSE VARIABLES TO RUNTIME;
        " >/dev/null 2>&1 || true
        echo " Ready."
        break
    fi
    echo -n "."
    sleep 1
    COUNT=$((COUNT+1))
done

if [ $COUNT -ge $MAX_WAIT ]; then
    echo " TIMEOUT"
    exit 1
fi
