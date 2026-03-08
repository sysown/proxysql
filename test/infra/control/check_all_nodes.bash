#!/usr/bin/env bash

TABLES=(mysql_servers mysql_users mysql_query_rules mysql_query_rules_fast_routing global_variables proxysql_servers mysql_galera_hostgroups mysql_group_replication_hostgroups mysql_replication_hostgroups mysql_hostgroup_attributes)

ALL_TABLES=()

for i in  ; do
        ALL_TABLES+=()
        ALL_TABLES+=("runtime_")
done

# The nodes in our containerized cluster
NODES="proxysql proxy-node1 proxy-node2 proxy-node3 proxy-node4 proxy-node5 proxy-node6 proxy-node7 proxy-node8 proxy-node9"

for host in  ; do
        # Use radmin/radmin for remote access between containers
        for i in  ; do
                echo "SELECT COUNT(*) FROM ;"
        done | mysql -u radmin -pradmin -h  -P 6032 > /dev/null &
done
