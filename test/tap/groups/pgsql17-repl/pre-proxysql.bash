#!/bin/bash
set -e
set -o pipefail
#
# change infra config for PostgreSQL 17 replication
# inherits env from tester script
#

# Derive Workspace relative to script
# Script is in test/tap/groups/pgsql17-repl/pre-proxysql.bash
# REPO_ROOT should be 4 levels up
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
INFRA_DIR="${REPO_ROOT}/test/infra"

# Set INFRA based on current folder name or fixed for this hook
INFRA="infra-pgsql17-repl"

echo "DEBUG: REPO_ROOT=${REPO_ROOT}"
echo "DEBUG: INFRA_DIR=${INFRA_DIR}"

# Stop any existing ProxySQL and its backend nodes
"${INFRA_DIR}/control/stop-proxysql-isolated.bash"

# Start a fresh ProxySQL
"${INFRA_DIR}/control/start-proxysql-isolated.bash"

# Start the specific PostgreSQL replication infra
# (this will configure ProxySQL via docker-proxy-post.bash)
cd "${INFRA_DIR}/${INFRA}"
./docker-compose-init.bash
cd - >/dev/null

# wait for infra to stabilize
sleep 10
