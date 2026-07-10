#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MySQL 9.5 Group Replication (3 nodes)..."
echo "========================================================================"

# Detect the unpacked MySQL version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MySQL tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MySQL version: ${MYSQL_VERSION}"

# Deploy 3-node Group Replication (single-primary)
# --base-port=3305 because dbdeployer assigns base+1 to the first node (node1=3306, node2=3307, node3=3308)
# Each -c flag adds a separate line to my.sandbox.cnf
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --topology=group \
    --single-primary \
    --nodes=3 \
    --bind-address=0.0.0.0 \
    --base-port=3305 \
    -c max_connections=500 \
    -c local_infile=ON \
    -c innodb_buffer_pool_size=128M \
    -c innodb_redo_log_capacity=64M \
    -c innodb_flush_log_at_trx_commit=2 \
    -c sync_binlog=0 \
    -c binlog_checksum=NONE \
    -c innodb_use_native_aio=0 \
    -c report_host=dbdeployer1.${INFRA}

echo "Group Replication deployed. Waiting for all nodes to be ready..."

# Determine the sandbox directory (GR topology uses group_sp_msb_* prefix)
SANDBOX_DIR=$(ls -d /root/sandboxes/group_sp_msb_* 2>/dev/null | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# dbdeployer GR layout: node1 (port 3306), node2 (port 3307), node3 (port 3308)
# dbdeployer default root password is 'msandbox'
DBDEPLOYER_ROOT_PASS="msandbox"
MYSQL_CMD="mysql -h127.0.0.1 -uroot -p${DBDEPLOYER_ROOT_PASS}"
NODE_PORTS=(3306 3307 3308)
NODE_NAMES=("node1" "node2" "node3")

# Wait for all 3 nodes to accept connections
for i in 0 1 2; do
    PORT="${NODE_PORTS[$i]}"
    NAME="${NODE_NAMES[$i]}"
    echo -n "Waiting for ${NAME} on port ${PORT}..."
    MAX_WAIT=60
    COUNT=0
    while ! ${MYSQL_CMD} -P${PORT} -e "SELECT 1" >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " TIMEOUT"
            exit 1
        fi
        echo -n "."
        sleep 1
        COUNT=$((COUNT + 1))
    done
    echo " OK"
done

# Wait for all 3 GR members to be ONLINE
echo -n "Waiting for Group Replication to stabilize..."
MAX_WAIT=60
COUNT=0
while true; do
    ONLINE=$(${MYSQL_CMD} -P3306 --batch -N -e \
        "SELECT COUNT(*) FROM performance_schema.replication_group_members WHERE MEMBER_STATE='ONLINE'" 2>/dev/null)
    if [ "$ONLINE" = "3" ]; then echo " OK (3 ONLINE)"; break; fi
    if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; exit 1; fi
    echo -n "."; sleep 2; COUNT=$((COUNT + 2))
done

# Create test users on PRIMARY only (GR replicates to all members)
# ROOT_PASSWORD and INFRA are passed via environment variables
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer-mysql95-gr}"

echo "Creating test users on primary (port 3306)..."

# NOTE: Do NOT use SET SQL_LOG_BIN=0 for GR — user changes must be
# replicated to all nodes via the binlog.
${MYSQL_CMD} -P3306 <<SQL

-- root user with dynamic password (both remote and localhost)
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'localhost' IDENTIFIED BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user needs extra GR privileges
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT USAGE, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'monitor'@'%';
GRANT SELECT ON sys.* TO 'monitor'@'%';
GRANT SELECT ON performance_schema.* TO 'monitor'@'%';

-- testuser
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- Cluster specific user
CREATE USER IF NOT EXISTS '${INFRA}'@'%' IDENTIFIED BY '${INFRA}';
GRANT ALL PRIVILEGES ON *.* TO '${INFRA}'@'%';

-- Databases
CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;

-- sbtest users
$(for j in $(seq 1 10); do
    echo "CREATE USER IF NOT EXISTS 'sbtest${j}'@'%' IDENTIFIED BY 'sbtest${j}';"
    for db in sysbench test t1 jdbc_test; do
        echo "GRANT ALL PRIVILEGES ON ${db}.* TO 'sbtest${j}'@'%';"
    done
done)

-- ssluser
CREATE USER IF NOT EXISTS 'ssluser'@'%' IDENTIFIED BY 'ssluser';
GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%';

-- user (generic)
CREATE USER IF NOT EXISTS 'user'@'%' IDENTIFIED BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';

FLUSH PRIVILEGES;
SQL

# Signal readiness via marker file (used by docker-mysql-post.bash)
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MySQL 9.5 Group Replication is ready."
echo "  Node 1 (primary):   port 3306"
echo "  Node 2 (secondary): port 3307"
echo "  Node 3 (secondary): port 3308"
echo "========================================================================"

# Keep container alive
exec sleep infinity
