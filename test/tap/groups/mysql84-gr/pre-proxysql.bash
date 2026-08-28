#!/usr/bin/env bash
set -e
set -o pipefail
#
# Pre-proxysql hook for mysql84-gr group.
# Runs on the HOST (not inside Docker). Uses docker exec to reach ProxySQL.
# The infra (infra-dbdeployer-mysql84-gr) is started by the framework AFTER this hook.
# This hook configures ProxySQL with GR-specific fallback hostgroups, users, and routing.
#

PROXY_CONTAINER="proxysql.${INFRA_ID}"
INFRA="${DEFAULT_MYSQL_INFRA:-infra-dbdeployer-mysql84-gr}"
MYSQL_HOST="${MYSQL_PRIMARY_HOST:-dbdeployer1}.${INFRA}"

run_admin() {
    docker exec ${PROXY_CONTAINER} mysql -uradmin -pradmin -h127.0.0.1 -P6032 -e "$1" 2>&1 | grep -vP 'mysql: .?Warning' || true
}

echo ">>> Pre-proxysql: configuring GR group (INFRA=${INFRA}, host=${MYSQL_HOST})"

# Wait for ProxySQL admin to be reachable
echo -n ">>> Pre-proxysql: waiting for ProxySQL admin..."
for i in $(seq 1 30); do
    if run_admin "SELECT 1" >/dev/null 2>&1; then echo " OK"; break; fi
    if [ $i -eq 30 ]; then echo " TIMEOUT"; exit 1; fi
    echo -n "."; sleep 1
done

# Use hostgroups from infra .env (WHG=3000, RHG=3001) — same as infra-config.sql
# so that mysql_group_replication_hostgroups manages these servers.
_WRHG="${WHG:-0}"
_RRHG="${RHG:-1}"

run_admin "
DELETE FROM mysql_servers WHERE hostgroup_id IN (${_WRHG},${_RRHG});
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${_WRHG},'${MYSQL_HOST}',3306,1,'${MYSQL_HOST}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${_RRHG},'${MYSQL_HOST}',3306,1,'${MYSQL_HOST}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${_RRHG},'${MYSQL_HOST}',3307,1,'${MYSQL_HOST}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (${_RRHG},'${MYSQL_HOST}',3308,1,'${MYSQL_HOST}');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
"

# Create default users with writer hostgroup as default
for MYUSER in root user testuser sbtest1 sbtest2 sbtest3 sbtest4 ssluser; do
    run_admin "
    INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('${MYUSER}','${MYUSER}',1,${_WRHG},'${INFRA}');
    UPDATE mysql_users SET default_hostgroup=${_WRHG},comment='${INFRA}' WHERE username='${MYUSER}';
    "
done
run_admin "LOAD MYSQL USERS TO RUNTIME; SAVE MYSQL USERS TO DISK;"

# Create basic read/write routing using GR hostgroups
run_admin "
DELETE FROM mysql_query_rules WHERE destination_hostgroup IN (${_WRHG},${_RRHG});
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (1,1,'root','^SELECT.*FOR UPDATE',${_WRHG},1);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (2,1,'root','^SELECT',${_RRHG},1);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (4,1,'testuser','^SELECT.*FOR UPDATE',${_WRHG},1);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (5,1,'testuser','^SELECT',${_RRHG},1);
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
"

echo ">>> Pre-proxysql: waiting for cluster to stabilize..."
sleep 5
