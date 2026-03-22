#!/usr/bin/env bash
set -e
set -o pipefail
#
# change infra config
# inherits env from tester script
#


# Start ProxySQL Cluster if available
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
"${REPO_ROOT}/test/infra/control/cluster_start.bash"
"${REPO_ROOT}/test/infra/control/cluster_init.bash"

# wait for cluster to stabilize
sleep 10
