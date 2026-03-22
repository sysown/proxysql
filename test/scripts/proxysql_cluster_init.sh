#!/bin/bash

. ../env.sh

# make sure we are in correct folder
trap popd EXIT
pushd $WORKSPACE/src


SECONDS=0
echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Cluster init ..."


( cat << EOF
SET admin-admin_credentials="admin:admin;radmin:radmin;cluster1:secret1pass";
SET admin-cluster_username="cluster1";
SET admin-cluster_password="secret1pass";
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("127.0.0.1",26001,0,"proxysql01");
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("127.0.0.1",26002,0,"proxysql02");
INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("127.0.0.1",26003,0,"proxysql03");
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK;
LOAD MYSQL VARIABLES TO RUNTIME;
LOAD PROXYSQL SERVERS TO RUNTIME;
SAVE PROXYSQL SERVERS TO DISK;
LOAD MYSQL QUERY RULES TO RUNTIME;
LOAD MYSQL USERS TO RUNTIME;
LOAD MYSQL QUERY RULES TO RUNTIME;
EOF
) | mysql -u admin -padmin -h 127.0.0.1 -P6032 2>&1

sleep 5

mysql -u admin -padmin -h 127.0.0.1 -P26001 -e 'INSERT INTO proxysql_servers (hostname,port,weight,comment) VALUES ("127.0.0.1",6032,0,"proxysql"); LOAD PROXYSQL SERVERS TO RUNTIME; SAVE PROXYSQL SERVERS TO DISK;' 2>&1

rm -f /tmp/check_all_nodes.bash || true
( cd ../test/cluster && bash ./install_scheduler.bash )


echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Cluster init DONE in ${SECONDS}s"
