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
#   proxy-node9: 6122

TABLES=(mysql_servers mysql_users mysql_query_rules mysql_query_rules_fast_routing global_variables proxysql_servers mysql_galera_hostgroups mysql_group_replication_hostgroups mysql_replication_hostgroups mysql_hostgroup_attributes)

ALL_TABLES=()
for i in ${!TABLES[@]}; do
    ALL_TABLES+=(${TABLES[$i]})
    ALL_TABLES+=("runtime_"${TABLES[$i]})
done

# Primary + up to 9 nodes, all on 127.0.0.1 with different ports
PORTS="6032 6042 6052 6062 6072 6082 6092 6102 6112 6122"

for port in ${PORTS}; do
    for i in ${!ALL_TABLES[@]}; do
        echo "SELECT COUNT(*) FROM ${ALL_TABLES[$i]};"
    done | mysql -u admin -padmin -h 127.0.0.1 -P ${port} > /dev/null 2>&1 &
done
