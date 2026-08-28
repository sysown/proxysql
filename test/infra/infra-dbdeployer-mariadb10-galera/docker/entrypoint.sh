#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MariaDB 10.11 Galera (3 nodes)..."
echo "========================================================================"

# Detect the unpacked MariaDB version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MariaDB tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MariaDB version: ${MYSQL_VERSION}"

# Deploy 3-node Galera cluster
# --base-port=3305: dbdeployer assigns base+1 to first node (node1=3306, node2=3307, node3=3308)
# -c wsrep_sst_method=mariabackup: rsync SST fails on fresh clusters where no binlogs exist yet
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --topology=galera \
    --nodes=3 \
    --bind-address=0.0.0.0 \
    --base-port=3305 \
    -c max_connections=500 \
    -c max_binlog_size=100M \
    -c wsrep_sst_method=mariabackup

echo "Galera deployed. Waiting for all nodes to be ready..."

# Determine the sandbox directory (Galera topology uses galera_msb_* prefix)
SANDBOX_DIR=$(ls -d /root/sandboxes/galera_msb_* 2>/dev/null | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# dbdeployer Galera layout: node1 (port 3306), node2 (port 3307), node3 (port 3308)
DBDEPLOYER_ROOT_PASS="msandbox"
MYSQL_CMD="mysql -h127.0.0.1 -uroot -p${DBDEPLOYER_ROOT_PASS}"
NODE_PORTS=(3306 3307 3308)
NODE_NAMES=("node1" "node2" "node3")

# Wait for all 3 nodes to accept connections
for i in 0 1 2; do
    PORT="${NODE_PORTS[$i]}"
    NAME="${NODE_NAMES[$i]}"
    echo -n "Waiting for ${NAME} on port ${PORT}..."
    MAX_WAIT=120
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

# Wait for Galera cluster to be synced on all nodes
echo -n "Waiting for Galera cluster to stabilize..."
MAX_WAIT=120
COUNT=0
while true; do
    SYNCED=0
    for PORT in 3306 3307 3308; do
        STATE=$(${MYSQL_CMD} -P${PORT} --batch -N -e \
            "SELECT Variable_value FROM information_schema.global_status WHERE Variable_name='wsrep_local_state'" 2>/dev/null || echo "")
        if [ "$STATE" = "4" ]; then
            SYNCED=$((SYNCED + 1))
        fi
    done
    if [ "$SYNCED" = "3" ]; then echo " OK (3 SYNCED)"; break; fi
    if [ $COUNT -ge $MAX_WAIT ]; then echo " TIMEOUT"; exit 1; fi
    echo -n "."; sleep 2; COUNT=$((COUNT + 2))
done

# Create test users on node1 only (Galera replicates to all members)
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer-mariadb10-galera}"

echo "Creating test users on node1 (port 3306)..."

# NOTE: Do NOT use SET SQL_LOG_BIN=0 for Galera — user changes must be
# replicated to all nodes via the binlog.
${MYSQL_CMD} -P3306 <<SQL

-- root user with dynamic password (MariaDB syntax)
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}';
ALTER USER 'root'@'localhost' IDENTIFIED BY '${ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;

-- Monitor user
CREATE USER IF NOT EXISTS 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT USAGE, REPLICATION CLIENT, SUPER ON *.* TO 'monitor'@'%';
GRANT SELECT ON sys.* TO 'monitor'@'%';
GRANT SELECT ON performance_schema.* TO 'monitor'@'%';

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

# Signal readiness via marker file
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MariaDB 10.11 Galera is ready."
echo "  Node 1: port 3306 (writable)"
echo "  Node 2: port 3307 (writable)"
echo "  Node 3: port 3308 (writable)"
echo "========================================================================"

# Keep container alive
exec sleep infinity
