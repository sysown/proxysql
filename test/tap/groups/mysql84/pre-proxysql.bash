#!/usr/bin/env bash
set -e
set -o pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
#
# mysql84 pre-proxysql hook
# Runs on the HOST after ProxySQL container is up, before test runner starts.
# All ProxySQL admin commands must go through docker exec.
#

export INFRA_ID="${INFRA_ID:-dev-$USER}"
PROXY_CONTAINER="proxysql.${INFRA_ID}"

MYSQL_CMD="docker exec ${PROXY_CONTAINER} mysql -uradmin -pradmin -h127.0.0.1 -P6032 -NB"

# Start ProxySQL Cluster if available
${REPO_ROOT}/test/infra/control/cluster_start.bash
${REPO_ROOT}/test/infra/control/cluster_init.bash

INFRA=infra-$(basename $(dirname "$0") | sed 's/-g[0-9]//' | sed 's/_.*//')

# cleanup
${MYSQL_CMD} -e " \
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
DELETE FROM pgsql_users; \
LOAD PGSQL USERS TO RUNTIME; \
SAVE PGSQL USERS TO DISK; \
DELETE FROM pgsql_servers; \
LOAD PGSQL SERVERS TO RUNTIME; \
SAVE PGSQL SERVERS TO DISK; \
"

# load environment for infra
source ${REPO_ROOT}/test/infra/${INFRA}/.env

# Start infra
${REPO_ROOT}/test/infra/${INFRA}/docker-compose-init.bash

# create default users
for MYUSER in root user testuser sbtest1 sbtest2 sbtest3 sbtest4 ssluser ; do
	${MYSQL_CMD} -e " \
	INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('${MYUSER}','${MYUSER}',1,${WHG},'${INFRA}'); \
	UPDATE mysql_users SET default_hostgroup=0,comment='${INFRA}' WHERE username='${MYUSER}'; \
	"
done
${MYSQL_CMD} -e " \
LOAD MYSQL USERS TO RUNTIME; \
SAVE MYSQL USERS TO DISK; \
"

# create default hostgroups
${MYSQL_CMD} -e " \
DELETE FROM mysql_servers WHERE hostgroup_id IN (0,1,2,3); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (0,'mysql1.${INFRA}',3306,1,'mysql1.${INFRA}'); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'mysql1.${INFRA}',3306,1,'mysql1.${INFRA}'); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'mysql2.${INFRA}',3306,1,'mysql2.${INFRA}'); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'mysql3.${INFRA}',3306,1,'mysql3.${INFRA}'); \
LOAD MYSQL SERVERS TO RUNTIME; \
SAVE MYSQL SERVERS TO DISK; \
"

# create default routing
${MYSQL_CMD} -e " \
DELETE FROM mysql_query_rules WHERE destination_hostgroup IN (0,1,2,3,4); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (1,1,'root','^SELECT.*FOR UPDATE',0,1); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (2,1,'root','^SELECT',1,1); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (4,1,'testuser','^SELECT.*FOR UPDATE',0,1); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (5,1,'testuser','^SELECT',1,1); \
LOAD MYSQL QUERY RULES TO RUNTIME; \
SAVE MYSQL QUERY RULES TO DISK; \
"

# wait for infra to stabilize
sleep 10
