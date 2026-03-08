#!/usr/bin/env bash
#
# change infra config for PostgreSQL 17 replication
# inherits env from tester script
#

INFRA=infra-$(basename $(dirname "$0") | sed 's/-g[0-9]//' | sed 's/_.*//')

# destroy running infras
/home/rene/proxysql/test/infra/control/infra-default/docker-compose-destroy.bash

# cleanup ProxySQL before starting new infra
psql -h127.0.0.1 -p6132 -Uadmin -dadmin -c " \
DELETE FROM pgsql_users; \
LOAD PGSQL USERS TO RUNTIME; \
SAVE PGSQL USERS TO DISK; \
DELETE FROM pgsql_servers; \
DELETE FROM pgsql_hostgroup_parameters; \
DELETE FROM pgsql_replication_hostgroups; \
LOAD PGSQL SERVERS TO RUNTIME; \
SAVE PGSQL SERVERS TO DISK; \
DELETE FROM pgsql_query_rules; \
LOAD PGSQL QUERY RULES TO RUNTIME; \
SAVE PGSQL QUERY RULES TO DISK; \
DELETE FROM mysql_users; \
LOAD MYSQL USERS TO RUNTIME; \
SAVE MYSQL USERS TO DISK; \
DELETE FROM mysql_servers; \
DELETE FROM mysql_replication_hostgroups; \
DELETE FROM mysql_group_replication_hostgroups; \
DELETE FROM mysql_galera_hostgroups; \
LOAD MYSQL SERVERS TO RUNTIME; \
SAVE MYSQL SERVERS TO DISK; \
DELETE FROM mysql_query_rules; \
LOAD MYSQL QUERY RULES TO RUNTIME; \
SAVE MYSQL QUERY RULES TO DISK; \
" 2>&1

# load environment for infra
source /home/rene/proxysql/test/infra/control/${INFRA}/.env

# Start infra (this will configure ProxySQL via docker-proxy-post.bash)
/home/rene/proxysql/test/infra/control/infra-docker-hoster/docker-compose-init.bash
/home/rene/proxysql/test/infra/control/${INFRA}/docker-compose-init.bash

# wait for infra to stabilize
sleep 10
