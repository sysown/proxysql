#!/usr/bin/env bash
set -e
set -o pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
#
# Start ProxySQL Cluster if available
# inherits env from tester script
#

${REPO_ROOT}/test/infra/control/cluster_start.bash
${REPO_ROOT}/test/infra/control/cluster_init.bash

# wait for cluster to stabilize
sleep 10
