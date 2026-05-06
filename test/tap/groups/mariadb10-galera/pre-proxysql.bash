#!/usr/bin/env bash
set -e
set -o pipefail
#
# Pre-proxysql hook for mariadb10-galera group.
# Runs on the HOST (not inside Docker). Uses docker exec to reach ProxySQL.
# The infra (infra-dbdeployer-mariadb10-galera) is started by the framework AFTER this hook.
# This hook configures ProxySQL with Galera-specific fallback hostgroups, users, and routing.
#

PROXY_CONTAINER="proxysql.${INFRA_ID}"
INFRA="${DEFAULT_MYSQL_INFRA:-infra-dbdeployer-mariadb10-galera}"
MYSQL_HOST="${MYSQL_PRIMARY_HOST:-dbdeployer1.${INFRA}}"
ADMIN_USER="${PROXYSQL_ADMIN_USER:-admin}"
ADMIN_PASS="${PROXYSQL_ADMIN_PASS:-admin}"

run_admin() {
    docker exec "${PROXY_CONTAINER}" mysql -u"${ADMIN_USER}" -p"${ADMIN_PASS}" -h127.0.0.1 -P6032 -e "$1" 2>&1 | grep -vP 'mysql: .?Warning' || true
}

echo ">>> Pre-proxysql: configuring Galera group (INFRA=${INFRA}, host=${MYSQL_HOST})"

# Wait for ProxySQL admin to be reachable
echo -n ">>> Pre-proxysql: waiting for ProxySQL admin..."
for i in $(seq 1 30); do
    if docker exec "${PROXY_CONTAINER}" mysql -u"${ADMIN_USER}" -p"${ADMIN_PASS}" -h127.0.0.1 -P6032 -e "SELECT 1" >/dev/null 2>&1; then
        echo " OK"
        break
    fi
    if [ $i -eq 30 ]; then echo " TIMEOUT"; exit 1; fi
    echo -n "."; sleep 1
done

# Create fallback hostgroups 0/1 with the Galera servers
run_admin "
DELETE FROM mysql_servers WHERE hostgroup_id IN (0,1,2,3);
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (0,'${MYSQL_HOST}',3306,1,'${MYSQL_HOST}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'${MYSQL_HOST}',3306,1,'${MYSQL_HOST}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'${MYSQL_HOST}',3307,1,'${MYSQL_HOST}');
INSERT INTO mysql_servers (hostgroup_id,hostname,port,max_replication_lag,comment) VALUES (1,'${MYSQL_HOST}',3308,1,'${MYSQL_HOST}');
LOAD MYSQL SERVERS TO RUNTIME;
SAVE MYSQL SERVERS TO DISK;
" || true

# Create default users with HG 0 as default
for MYUSER in root user testuser sbtest1 sbtest2 sbtest3 sbtest4 mariadbuser mariadbuserff ssluser; do
    run_admin "
    INSERT OR IGNORE INTO mysql_users (username,password,active,default_hostgroup,comment) VALUES ('${MYUSER}','${MYUSER}',1,0,'${INFRA}');
    UPDATE mysql_users SET default_hostgroup=0,comment='${INFRA}' WHERE username='${MYUSER}';
    " || true
done
run_admin "LOAD MYSQL USERS TO RUNTIME; SAVE MYSQL USERS TO DISK;" || true

# Create basic read/write routing
run_admin "
DELETE FROM mysql_query_rules WHERE destination_hostgroup IN (0,1,2,3,4);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (1,1,'root','^SELECT.*FOR UPDATE',0,1);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (2,1,'root','^SELECT',1,1);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (4,1,'testuser','^SELECT.*FOR UPDATE',0,1);
INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply) VALUES (5,1,'testuser','^SELECT',1,1);
LOAD MYSQL QUERY RULES TO RUNTIME;
SAVE MYSQL QUERY RULES TO DISK;
" || true

echo ">>> Pre-proxysql: waiting for cluster to stabilize..."
sleep 5
