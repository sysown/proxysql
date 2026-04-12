#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MySQL 5.7 replication (3 nodes)..."
echo "========================================================================"

# Detect the unpacked MySQL version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MySQL tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MySQL version: ${MYSQL_VERSION}"

# Deploy 3-node replication with GTID
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --nodes=3 \
    --gtid \
    --bind-address=0.0.0.0 \
    --base-port=3306 \
    --my-cnf-options="log-slave-updates,binlog_format=ROW,max_connections=500,innodb_buffer_pool_size=128M,innodb_log_file_size=32M,innodb_flush_log_at_trx_commit=2,sync_binlog=0,binlog_checksum=NONE,show_compatibility_56=ON" \
    --repl-crash-safe

echo "Replication deployed. Waiting for all nodes to be ready..."

# Determine the sandbox directory
SANDBOX_DIR=$(ls -d /root/sandboxes/rsandbox_* | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# Wait for all 3 nodes to accept connections
for NODE_NUM in 1 2 3; do
    PORT=$((3305 + NODE_NUM))
    echo -n "Waiting for node${NODE_NUM} on port ${PORT}..."
    MAX_WAIT=60
    COUNT=0
    while ! "${SANDBOX_DIR}/node${NODE_NUM}/use" -e "SELECT 1" >/dev/null 2>&1; do
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

# Create test users on all 3 nodes
# ROOT_PASSWORD and INFRA are passed via environment variables
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer57}"

echo "Creating test users on all nodes..."
for NODE_NUM in 1 2 3; do
    NODE_SCRIPT="${SANDBOX_DIR}/node${NODE_NUM}/use"
    echo "Configuring users on node${NODE_NUM}..."

    "${NODE_SCRIPT}" <<SQL
SET SQL_LOG_BIN=0;

-- root user with dynamic password
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT USAGE, REPLICATION CLIENT ON *.* TO 'monitor'@'%';

-- testuser
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- Cluster specific user
CREATE USER IF NOT EXISTS '${INFRA}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${INFRA}';
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
CREATE USER IF NOT EXISTS 'ssluser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'ssluser';
GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%';

-- user (generic)
CREATE USER IF NOT EXISTS 'user'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';

FLUSH PRIVILEGES;
SQL
done

# Signal readiness via marker file (used by docker-mysql-post.bash)
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MySQL 5.7 replication is ready."
echo "  Node 1 (writer): port 3306"
echo "  Node 2 (replica): port 3307"
echo "  Node 3 (replica): port 3308"
echo "========================================================================"

# Keep container alive
exec sleep infinity
