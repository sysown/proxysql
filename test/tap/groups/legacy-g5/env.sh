# Legacy G5: cluster sync tests that manage their own ProxySQL replicas.
# Use only 1 cluster node to avoid multi-node sync interference during
# cluster isolation steps. These tests remove the primary from
# proxysql_servers and expect the change to propagate cleanly — with
# multiple nodes syncing from each other, the removal can get reverted.
export PROXYSQL_CLUSTER_NODES=1

# Inherit defaults from the base legacy group
source "$(dirname "${BASH_SOURCE[0]}")/../legacy/env.sh"
