#!/usr/bin/env bash
set -e
set -o pipefail
#
# Start ProxySQL Cluster if available
# inherits env from tester script
#

/home/rene/proxysql/test/infra/control/cluster_start.bash
/home/rene/proxysql/test/infra/control/cluster_init.bash

# wait for cluster to stabilize
sleep 10
