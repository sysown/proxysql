#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MariaDB 10.11 replication (3 nodes)..."
echo "========================================================================"

# Detect the unpacked MariaDB version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MariaDB tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MariaDB version: ${MYSQL_VERSION}"

# Deploy 3-node replication (no --gtid, no --repl-crash-safe for MariaDB)
# --base-port=3305 because dbdeployer assigns base+1 to the first node (master=3306, node1=3307, node2=3308)
# Each -c flag adds a separate line to my.sandbox.cnf
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --nodes=3 \
    --bind-address=0.0.0.0 \
    --base-port=3305 \
    -c log-slave-updates \
    -c max_connections=500 \
    -c max_binlog_size=100M \
    -c plugin_load_add=ha_blackhole

echo "Replication deployed. Waiting for all nodes to be ready..."

# Determine the sandbox directory
SANDBOX_DIR=$(ls -d /root/sandboxes/rsandbox_* | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# dbdeployer replication layout: master (port 3306), node1 (port 3307), node2 (port 3308)
# dbdeployer default root password is 'msandbox'
DBDEPLOYER_ROOT_PASS="msandbox"
MYSQL_CMD="mysql -h127.0.0.1 -uroot -p${DBDEPLOYER_ROOT_PASS}"
NODE_PORTS=(3306 3307 3308)
NODE_NAMES=("master" "node1" "node2")

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

# Create test users on all 3 nodes
# ROOT_PASSWORD and INFRA are passed via environment variables
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer-mariadb10}"

echo "Creating test users on all nodes..."
for PORT in "${NODE_PORTS[@]}"; do
    echo "Configuring users on port ${PORT}..."

    ${MYSQL_CMD} -P${PORT} <<SQL
SET SQL_LOG_BIN=0;

-- root user with dynamic password (MariaDB syntax)
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
SET PASSWORD FOR 'root'@'%' = PASSWORD('${ROOT_PASSWORD}');
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${ROOT_PASSWORD}');
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Replication user
CREATE USER IF NOT EXISTS 'rpl_user'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO 'rpl_user'@'%';

-- Monitor user
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT USAGE, REPLICATION CLIENT, SUPER ON *.* TO 'monitor'@'%';

-- testuser
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- MariaDB specific users for Fast Forward tests
CREATE USER IF NOT EXISTS 'mariadbuser'@'%' IDENTIFIED BY 'mariadbuser';
GRANT ALL PRIVILEGES ON *.* TO 'mariadbuser'@'%';
CREATE USER IF NOT EXISTS 'mariadbuserff'@'%' IDENTIFIED BY 'mariadbuserff';
GRANT ALL PRIVILEGES ON *.* TO 'mariadbuserff'@'%';

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
done

# Set read_only=1 on replicas (ports 3307, 3308) to match infra-mariadb10 behavior
# MariaDB doesn't have super_read_only
echo "Setting read_only on replicas..."
for PORT in 3307 3308; do
    mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" -P${PORT} -e "SET GLOBAL read_only=1;"
    echo "  port ${PORT}: read_only=1"
done

# Signal readiness via marker file (used by docker-mysql-post.bash)
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MariaDB 10.11 replication is ready."
echo "  Node 1 (writer): port 3306"
echo "  Node 2 (replica): port 3307"
echo "  Node 3 (replica): port 3308"
echo "========================================================================"

# Keep container alive
exec sleep infinity
