#!/bin/bash
set -e
set -o pipefail

# Derive Workspace relative to script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
export WORKSPACE="${REPO_ROOT}"

source "${SCRIPT_DIR}/docker-fs-helper.bash"

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

PROXY_CONTAINER="proxysql.${INFRA_ID}"
NETWORK_NAME="${INFRA_ID}_backend"

echo ">>> Stopping ProxySQL Infrastructure for ${INFRA_ID}"
docker ps -a --format '{{.Names}}' | grep "${INFRA_ID}" | grep -v "test-runner" | xargs -r docker rm -f >/dev/null 2>&1 || true

if [ -f /.dockerenv ]; then
    RUNNER_ID=$(hostname)
    echo ">>> Disconnecting Runner container from network"
    docker network disconnect -f "${NETWORK_NAME}" "${RUNNER_ID}" >/dev/null 2>&1 || true
fi

echo ">>> Removing Network: ${NETWORK_NAME}"
for i in {1..5}; do
    if docker network rm "${NETWORK_NAME}" >/dev/null 2>&1; then
        echo ">>> Network ${NETWORK_NAME} removed."
        break
    fi
    sleep 1
done

echo ">>> Log permissions cleanup"
INFRA_LOGS_PATH="${WORKSPACE}/ci_infra_logs"
if [ -d "${INFRA_LOGS_PATH}/${INFRA_ID}" ]; then
    chmod -R 777 "${INFRA_LOGS_PATH}/${INFRA_ID}" 2>/dev/null || \
    docker_fs_exec "chmod -R 777 ." "${INFRA_LOGS_PATH}/${INFRA_ID}" >/dev/null 2>&1 || true
fi
