#!/bin/bash
TABLES=(mysql_servers mysql_users mysql_query_rules mysql_query_rules_fast_routing global_variables proxysql_servers mysql_galera_hostgroups mysql_group_replication_hostgroups mysql_replication_hostgroups mysql_hostgroup_attributes)

ALL_TABLES=()

for i in ${!TABLES[@]} ; do
	ALL_TABLES+=(${TABLES[$i]})
	ALL_TABLES+=("runtime_"${TABLES[$i]})
done

#for i in ${!ALL_TABLES[@]} ; do
#	echo "SELECT * FROM ${ALL_TABLES[$i]};"
#done

for p in 6032 `seq 26001 26009` ; do
	for i in ${!ALL_TABLES[@]} ; do
		echo "SELECT COUNT(*) FROM ${ALL_TABLES[$i]};"
	done | mysql -u admin -padmin -h 127.0.0.1 -P$p > /dev/null 2> /dev/null &
done
