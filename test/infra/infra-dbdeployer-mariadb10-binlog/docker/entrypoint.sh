#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MariaDB 10.11 replication + binlog readers"
echo "========================================================================"

# Detect the unpacked MariaDB version
MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MariaDB tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MariaDB version: ${MYSQL_VERSION}"

INFRA="${INFRA:-infra-dbdeployer-mariadb10-binlog}"
ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
TLS_DIR="/etc/mysql-tls"
TLS_CA="${TLS_DIR}/ca.pem"
TLS_CERT="${TLS_DIR}/server-cert.pem"
TLS_KEY="${TLS_DIR}/server-key.pem"

# ---------------------------------------------------------------------------
# Generate the TLS material.
#
# dbdeployer provisions SSL certificates for MySQL sandboxes but not for
# MariaDB ones -- a MariaDB sandbox datadir contains no ca.pem. Rather than
# start the reader with --ssl-mode=DISABLED and lose the encrypted-replication
# path that the MySQL binlog infras exercise, generate a self-signed CA and
# server certificate here and hand them to MariaDB.
#
# Certificate verification stays disabled on the client (see the reader flags
# below), which is the same deliberate CI-only decision the MySQL binlog infras
# make: these are throwaway self-signed certs in an isolated sandbox.
# ---------------------------------------------------------------------------
gen_tls_certs() {
    if [ -f "${TLS_CA}" ] && [ -f "${TLS_CERT}" ] && [ -f "${TLS_KEY}" ]; then
        echo "TLS material already present in ${TLS_DIR}; reusing it."
        return 0
    fi

    echo "Generating self-signed TLS material in ${TLS_DIR}..."
    rm -rf "${TLS_DIR}"
    mkdir -p "${TLS_DIR}"
    chmod 700 "${TLS_DIR}"

    # SANs cover every name the reader or a test may use to reach a node. The
    # client does not verify, but a correct SAN keeps the cert usable for
    # anything that does.
    SAN="DNS:localhost,DNS:dbdeployer1,DNS:dbdeployer1.${INFRA},DNS:dbdeployer1.infra-dbdeployer-mariadb10-binlog,IP:127.0.0.1"

    openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
        -keyout "${TLS_DIR}/ca-key.pem" \
        -out "${TLS_CA}" \
        -subj "/CN=proxysql-mariadb-binlog-infra-ca" 2>/dev/null

    openssl req -newkey rsa:2048 -sha256 -nodes \
        -keyout "${TLS_KEY}" \
        -out "${TLS_DIR}/server-req.pem" \
        -subj "/CN=dbdeployer1.${INFRA}" 2>/dev/null

    openssl x509 -req -in "${TLS_DIR}/server-req.pem" -days 3650 \
        -CA "${TLS_CA}" -CAkey "${TLS_DIR}/ca-key.pem" -CAcreateserial \
        -out "${TLS_CERT}" -sha256 \
        -extfile <(printf "subjectAltName=%s\n" "${SAN}") 2>/dev/null

    rm -f "${TLS_DIR}/server-req.pem" "${TLS_DIR}/ca-key.pem" "${TLS_DIR}/ca.srl"
    chmod 644 "${TLS_CA}" "${TLS_CERT}"
    chmod 600 "${TLS_KEY}"

    openssl x509 -in "${TLS_CERT}" -noout -subject -ext subjectAltName 2>/dev/null \
        | sed 's/^/    /'
    echo "TLS material generated."
}

gen_tls_certs

# Deploy 3-node replication.
#
# No --gtid and no --repl-crash-safe: those are MySQL options and dbdeployer
# rejects them for MariaDB. MariaDB's equivalent of GTID is the domain id, which
# the reader reads from @@gtid_binlog_pos; gtid_strict_mode below controls how
# a replica advances its own position.
#
# --base-port=3305 because dbdeployer assigns base+1 to the first node
# (master=3306, node1=3307, node2=3308). Each -c flag adds a line to
# my.sandbox.cnf.
dbdeployer deploy replication "${MYSQL_VERSION}" \
    --nodes=3 \
    --bind-address=0.0.0.0 \
    --base-port=3305 \
    -c log-slave-updates \
    -c max_connections=500 \
    -c max_binlog_size=100M \
    -c plugin_load_add=ha_blackhole \
    -c binlog_format=ROW \
    -c gtid_strict_mode=1 \
    -c ssl_ca="${TLS_CA}" \
    -c ssl_cert="${TLS_CERT}" \
    -c ssl_key="${TLS_KEY}"

echo "Replication deployed. Waiting for all nodes to be ready..."

SANDBOX_DIR=$(ls -d /root/sandboxes/rsandbox_* | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

# dbdeployer replication layout: master (3306), node1 (3307), node2 (3308).
# dbdeployer's default root password is 'msandbox'.
DBDEPLOYER_ROOT_PASS="msandbox"
MYSQL_CMD="mysql -h127.0.0.1 -uroot -p${DBDEPLOYER_ROOT_PASS}"
NODE_PORTS=(3306 3307 3308)
NODE_NAMES=("master" "node1" "node2")

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

# Fail loudly if TLS did not actually come up. Without this the reader would
# simply refuse to connect later, and the reason would be a confusing
# connector error rather than "the infra is not configured for TLS".
for PORT in "${NODE_PORTS[@]}"; do
    HAVE_SSL=$(${MYSQL_CMD} -P${PORT} -N -B -e "SHOW VARIABLES LIKE 'have_ssl';" 2>/dev/null | awk '{print $2}')
    if [ "${HAVE_SSL}" != "YES" ]; then
        echo "ERROR: MariaDB on port ${PORT} reports have_ssl=${HAVE_SSL}, expected YES."
        echo "       The binlog reader requires TLS, so the infra would not work."
        exit 1
    fi
done
echo "TLS enabled on all nodes (have_ssl=YES)."

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

-- Binlog reader user (required for proxysql_binlog_reader)
CREATE USER IF NOT EXISTS 'binlog'@'%' IDENTIFIED BY 'binlog';
GRANT USAGE, REPLICATION CLIENT, REPLICATION SLAVE ON *.* TO 'binlog'@'%';

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

-- sbtest users (sbtest7 and sbtest8 specifically needed for binlog tests)
$(for j in $(seq 1 10); do
    echo "CREATE USER IF NOT EXISTS 'sbtest${j}'@'%' IDENTIFIED BY 'sbtest${j}';"
    for db in sysbench test t1 jdbc_test; do
        echo "GRANT ALL PRIVILEGES ON ${db}.* TO 'sbtest${j}'@'%';"
    done
done)

-- user (generic)
CREATE USER IF NOT EXISTS 'user'@'%' IDENTIFIED BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%';

FLUSH PRIVILEGES;
SQL
done

# Set read_only on the replicas. MariaDB has no super_read_only, and we want the
# same writer/replica split the MySQL binlog infras rely on for causal reads.
#
# These connections use ROOT_PASSWORD, not dbdeployer's original 'msandbox':
# the user block above reset root@localhost to the dynamic password, so 'msandbox'
# no longer authenticates by this point.
echo "Setting read_only on replicas..."
for PORT in 3307 3308; do
    mysql -h127.0.0.1 -uroot -p"${ROOT_PASSWORD}" -P${PORT} -e "SET GLOBAL read_only=1;"
    echo "  port ${PORT}: read_only=1"
done

# Start proxysql_binlog_reader processes (one per MariaDB node).
# Each reader connects to its node and listens on a GTID port.
# TLS is required and certificate verification is disabled: encryption stays on,
# the trust decision does not, which is the deliberate CI-only decision the
# MySQL binlog infras make with their generated self-signed certificates.
# test/tap/groups/test_binlog_reader_infra.py asserts these two flags.
echo "Starting binlog readers..."
mkdir -p /var/log/mysqlbinlog

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
        --ssl-mode=REQUIRED \
        --ssl-verify-server-cert=0 \
        --ssl-ca "${TLS_CA}" \
        -f >> /var/log/mysqlbinlog/reader_${MYSQL_PORT}.log 2>&1 &
done

sleep 2
for i in 0 1 2; do
    READER_PORT="${READER_PORTS[$i]}"
    echo -n "  Checking reader on port ${READER_PORT}..."
    MAX_WAIT=10
    COUNT=0
    while ! bash -c "echo > /dev/tcp/127.0.0.1/${READER_PORT}" 2>/dev/null; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " NOT RESPONDING"
            echo "  >>> reader log:"
            tail -n 20 "/var/log/mysqlbinlog/reader_${NODE_PORTS[$i]}.log" 2>/dev/null || true
            exit 1
        fi
        echo -n "."
        sleep 1
        COUNT=$((COUNT + 1))
    done
    echo " OK"
done

# Signal readiness via marker file (used by docker-compose-init.bash)
touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MariaDB ${MYSQL_VERSION} replication + binlog readers is ready."
echo "  Node 1 (writer):  port 3306, GTID reader port 6020"
echo "  Node 2 (replica): port 3307, GTID reader port 6021"
echo "  Node 3 (replica): port 3308, GTID reader port 6022"
echo "========================================================================"

# Keep container alive
exec sleep infinity
