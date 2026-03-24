#!/usr/bin/env bash
set -e
set -o pipefail
#
# Pre-proxysql hook for unified CI
# Starts ProxySQL cluster nodes if needed.
# Infrastructure and user/server provisioning is handled by
# ensure-infras.bash and docker-proxy-post.bash.
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export WORKSPACE="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"

# Start ProxySQL Cluster if available
"${WORKSPACE}/test/infra/control/cluster_start.bash"
"${WORKSPACE}/test/infra/control/cluster_init.bash"

# wait for infra to stabilize
sleep 10
