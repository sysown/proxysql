#!/usr/bin/env bash
#
# Scheduler script: polls all ProxySQL cluster nodes to keep them active.
# Runs inside the ProxySQL container where all nodes are on 127.0.0.1.
#
# Port scheme:
#   Primary:     6032
#   proxy-node1: 6042
#   proxy-node2: 6052
#   ...
#   proxy-node6: 6092 (default)

TABLES=(mysql_servers mysql_users mysql_query_rules mysql_query_rules_fast_routing global_variables proxysql_servers mysql_galera_hostgroups mysql_group_replication_hostgroups mysql_replication_hostgroups mysql_hostgroup_attributes)

ALL_TABLES=()
for i in ${!TABLES[@]}; do
    ALL_TABLES+=(${TABLES[$i]})
    ALL_TABLES+=("runtime_"${TABLES[$i]})
done

# Poll exactly the configured peers, including explicit size/disabled overrides.
NUM_NODES=${PROXYSQL_CLUSTER_NODES:-6}
PORTS="6032"
for ((node = 1; node <= NUM_NODES; node++)); do
    PORTS="${PORTS} $((6032 + node * 10))"
done

for port in ${PORTS}; do
    for i in ${!ALL_TABLES[@]}; do
        echo "SELECT COUNT(*) FROM ${ALL_TABLES[$i]};"
    done | mysql -u admin -padmin -h 127.0.0.1 -P ${port} > /dev/null 2>&1 &
done
