#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MySQL 8.4 replication + binlog readers..."
echo "========================================================================"

# Detect the unpacked MySQL version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MySQL tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MySQL version: ${MYSQL_VERSION}"

# Deploy 3-node replication with GTID
# --base-port=3305 because dbdeployer assigns base+1 to the first node (master=3306, node1=3307, node2=3308)
# Each -c flag adds a separate line to my.sandbox.cnf
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --nodes=3 \
    --gtid \
    --repl-crash-safe \
    --bind-address=0.0.0.0 \
    --base-port=3305 \
    -c log-replica-updates \
    -c binlog_format=ROW \
    -c max_connections=500 \
    -c local_infile=ON \
    -c innodb_buffer_pool_size=128M \
    -c innodb_redo_log_capacity=64M \
    -c innodb_flush_log_at_trx_commit=2 \
    -c sync_binlog=0 \
    -c binlog_checksum=NONE \
    -c session_track_gtids=OWN_GTID \
    -c slave_net_timeout=4 \
    -c mysql_native_password=ON \
    -c innodb_use_native_aio=0

echo "Replication deployed. Waiting for all nodes to be ready..."

# Determine the sandbox directory
SANDBOX_DIR=$(ls -d /root/sandboxes/rsandbox_* | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# dbdeployer replication layout: master (port 3306), node1 (port 3307), node2 (port 3308)
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
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer-mysql84-binlog}"

echo "Creating test users on all nodes..."
for PORT in "${NODE_PORTS[@]}"; do
    echo "Configuring users on port ${PORT}..."

    ${MYSQL_CMD} -P${PORT} <<SQL
SET SQL_LOG_BIN=0;

-- root user with dynamic password (both remote and localhost)
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'localhost' IDENTIFIED WITH 'mysql_native_password' BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT USAGE, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'monitor'@'%';

-- testuser
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'testuser';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

-- Binlog reader user (required for proxysql_binlog_reader)
CREATE USER IF NOT EXISTS 'binlog'@'%' IDENTIFIED WITH 'mysql_native_password' BY 'binlog';
GRANT USAGE, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'binlog'@'%';

-- Cluster specific user
CREATE USER IF NOT EXISTS '${INFRA}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${INFRA}';
GRANT ALL PRIVILEGES ON *.* TO '${INFRA}'@'%';

-- Databases
CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;

-- sbtest users (sbtest7 and sbtest8 specifically needed for binlog tests)
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

# Set read_only=1 on replicas (ports 3307, 3308) to match infra-mysql84-binlog behavior
echo "Setting read_only on replicas..."
for PORT in 3307 3308; do
    mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" -P${PORT} -e "SET GLOBAL read_only=1; SET GLOBAL super_read_only=1;"
    echo "  port ${PORT}: read_only=1, super_read_only=1"
done

# Start proxysql_binlog_reader processes (one per MySQL node)
# Each reader connects to its MySQL node and listens on a GTID port
echo "Starting binlog readers..."
mkdir -p /var/log/mysqlbinlog

NODE_PORTS=(3306 3307 3308)
READER_PORTS=(6020 6021 6022)
for i in 0 1 2; do
    MYSQL_PORT="${NODE_PORTS[$i]}"
    READER_PORT="${READER_PORTS[$i]}"
    echo "  Starting reader for port ${MYSQL_PORT} -> GTID port ${READER_PORT}..."
    proxysql_binlog_reader \
        -h 127.0.0.1 \
        -u binlog \
        -p binlog \
        -P ${MYSQL_PORT} \
        -l ${READER_PORT} \
        -f >> /var/log/mysqlbinlog/reader_${MYSQL_PORT}.log 2>&1 &
done

# Wait briefly for readers to start, then verify they're listening
sleep 2
for i in 0 1 2; do
    READER_PORT="${READER_PORTS[$i]}"
    echo -n "  Checking reader on port ${READER_PORT}..."
    MAX_WAIT=10
    COUNT=0
    while ! bash -c "echo > /dev/tcp/127.0.0.1/${READER_PORT}" 2>/dev/null; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " WARNING: reader on port ${READER_PORT} not responding (continuing anyway)"
            break
        fi
        sleep 1
        COUNT=$((COUNT + 1))
    done
    echo " OK"
done

# Signal readiness via marker file (used by docker-compose-init.bash)
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MySQL 8.4 replication + binlog readers is ready."
echo "  Node 1 (writer):  port 3306, GTID reader port 6020"
echo "  Node 2 (replica): port 3307, GTID reader port 6021"
echo "  Node 3 (replica): port 3308, GTID reader port 6022"
echo "========================================================================"

# Keep container alive
exec sleep infinity
