#!/usr/bin/env bash
#
# change infra config
# inherits env from tester script
#

[[ $(mysql --skip-ssl-verify-server-cert -h 2>&1) =~ skip-ssl-verify-server-cert ]] || export SSLOPT=--skip-ssl-verify-server-cert

INFRA=infra-$(basename $(dirname "$0") | sed 's/-g[0-9]//' | sed 's/_.*//')

# destroy running infras
$JENKINS_SCRIPTS_PATH/infra-default/docker-compose-destroy.bash
# cleanup
mysql ${SSLOPT} -h127.0.0.1 -P6032 -uadmin -padmin -e " \
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
#DELETE FROM pgsql_query_rules; \
#LOAD PGSQL QUERY RULES TO RUNTIME; \
#SAVE PGSQL QUERY RULES TO DISK; \
" 2>&1 | grep -vP 'mysql: .?Warning'

# load environment for infra
source $JENKINS_SCRIPTS_PATH/${INFRA}/.env

# Start infra
$JENKINS_SCRIPTS_PATH/infra-docker-hoster/docker-compose-init.bash
$JENKINS_SCRIPTS_PATH/${INFRA}/docker-compose-init.bash

# create default users
for MYUSER in root user testuser sbtest1 sbtest2 sbtest3 sbtest4 ssluser ; do
	# FIXME: using 0 as default hostgroup
	mysql ${SSLOPT} -h127.0.0.1 -P6032 -uadmin -padmin -e " \
	INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) values ('${MYUSER}','${MYUSER}',1,${WHG},'${INFRA}'); \
	UPDATE mysql_users SET default_hostgroup=0,comment='${INFRA}' WHERE username='${MYUSER}'; \
	" 2>&1 | grep -vP 'mysql: .?Warning'
done
mysql ${SSLOPT} -h127.0.0.1 -P6032 -uadmin -padmin -e " \
LOAD MYSQL USERS TO RUNTIME; \
SAVE MYSQL USERS TO DISK; \
" 2>&1 | grep -vP 'mysql: .?Warning'

# create default hostgroups
mysql ${SSLOPT} -h127.0.0.1 -P6032 -uadmin -padmin -e " \
DELETE FROM mysql_servers WHERE hostgroup_id IN (0,1,2,3); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (0,'mysql1.${INFRA}',3306,1,'mysql1.${INFRA}'); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'mysql1.${INFRA}',3306,1,'mysql1.${INFRA}'); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'mysql2.${INFRA}',3306,1,'mysql2.${INFRA}'); \
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'mysql3.${INFRA}',3306,1,'mysql3.${INFRA}'); \
LOAD MYSQL SERVERS TO RUNTIME; \
SAVE MYSQL SERVERS TO DISK; \
" 2>&1 | grep -vP 'mysql: .?Warning'

# create default routing
mysql ${SSLOPT} -h127.0.0.1 -P6032 -uadmin -padmin -e " \
DELETE FROM mysql_query_rules WHERE destination_hostgroup IN (0,1,2,3,4); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (1,1,'root','^SELECT.*FOR UPDATE',0,1); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (2,1,'root','^SELECT',1,1); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (4,1,'testuser','^SELECT.*FOR UPDATE',0,1); \
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (5,1,'testuser','^SELECT',1,1); \
LOAD MYSQL QUERY RULES TO RUNTIME; \
SAVE MYSQL QUERY RULES TO DISK; \
" 2>&1 | grep -vP 'mysql: .?Warning'

# wait for infra to stabilize
sleep 10
