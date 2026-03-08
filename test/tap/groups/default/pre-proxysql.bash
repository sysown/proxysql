#!/usr/bin/env bash
#
# change infra config
# inherits env from tester script
#


# Start ProxySQL Cluster if available
/home/rene/proxysql/test/infra/control/cluster_start.bash
/home/rene/proxysql/test/infra/control/cluster_init.bash

# wait for cluster to stabilize
sleep 10
