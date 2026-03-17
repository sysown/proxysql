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

# Default INFRA_ID if not provided
export INFRA_ID="${INFRA_ID:-dev-$USER}"

PRIMARY="proxysql.${INFRA_ID}"
SCHEDULER_SCRIPT="${SCRIPT_DIR}/check_all_nodes.bash"

echo ">>> Installing Scheduler on Cluster Nodes..."

install_on_host() {
    local host=$1
    echo ">>> Installing scheduler on ${host}"
    docker cp "${SCHEDULER_SCRIPT}" "${host}:/tmp/check_all_nodes.bash"
    docker exec "${host}" chmod +x /tmp/check_all_nodes.bash
    
    docker exec -i "${host}" mysql -uadmin -padmin -h127.0.0.1 -P6032 <<SQL
INSERT OR REPLACE INTO scheduler (interval_ms, filename) VALUES (12000, '/tmp/check_all_nodes.bash');
LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;
SQL
}

# Install on Primary
install_on_host "${PRIMARY}"

# Install on all other nodes
NUM_NODES=${PROXYSQL_CLUSTER_NODES:-9}
for i in $(seq 1 "${NUM_NODES}"); do
    install_on_host "proxy-node${i}.${INFRA_ID}"
done
