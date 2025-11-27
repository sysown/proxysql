#!/usr/bin/env bash
#
# change infra config
# inherits env from tester script
#


# Start ProxySQL Cluster if available
$JENKINS_SCRIPTS_PATH/cluster_start.bash
$JENKINS_SCRIPTS_PATH/cluster_init.bash

# wait for cluster to stabilize
sleep 10
