#!/bin/bash
set -e
set -o pipefail

echo "========================================================================"
echo "dbdeployer entrypoint: deploying MySQL 5.6 single sandbox..."
echo "========================================================================"

MYSQL_VERSION=$(ls /root/opt/mysql/ | head -1)
if [ -z "${MYSQL_VERSION}" ]; then
    echo "ERROR: No MySQL tarball found in /root/opt/mysql/"
    exit 1
fi
echo "Using MySQL version: ${MYSQL_VERSION}"

mkdir -p /root/certs
if [ ! -f /root/certs/ca.pem ]; then
    openssl genrsa 2048 > /root/certs/ca-key.pem
    openssl req -new -x509 -nodes -days 3650 -key /root/certs/ca-key.pem -subj "/CN=ProxySQL MySQL56 Test CA" > /root/certs/ca.pem
    openssl req -newkey rsa:2048 -days 3650 -nodes -keyout /root/certs/server-key.pem -subj "/CN=dbdeployer1.infra-dbdeployer-mysql56-single" > /root/certs/server-req.pem
    openssl rsa -in /root/certs/server-key.pem -out /root/certs/server-key.pem
    openssl x509 -req -in /root/certs/server-req.pem -days 3650 -CA /root/certs/ca.pem -CAkey /root/certs/ca-key.pem -set_serial 01 > /root/certs/server-cert.pem
    chmod 600 /root/certs/server-key.pem
fi

dbdeployer deploy single "${MYSQL_VERSION}" \
    --port 3306 \
    --bind-address=0.0.0.0 \
    -c server-id=561 \
    -c log-bin=mysql-bin \
    -c log-slave-updates \
    -c binlog_format=ROW \
    -c max_connections=500 \
    -c innodb_buffer_pool_size=128M \
    -c innodb_log_file_size=32M \
    -c innodb_flush_log_at_trx_commit=2 \
    -c sync_binlog=0 \
    -c gtid_mode=ON \
    -c enforce_gtid_consistency=true \
    -c ssl-ca=/root/certs/ca.pem \
    -c ssl-cert=/root/certs/server-cert.pem \
    -c ssl-key=/root/certs/server-key.pem

SANDBOX_DIR=$(ls -d /root/sandboxes/msb_* | head -1)
if [ -z "${SANDBOX_DIR}" ]; then
    echo "ERROR: Sandbox directory not found"
    exit 1
fi
echo "Sandbox directory: ${SANDBOX_DIR}"

DBDEPLOYER_ROOT_PASS="msandbox"
MYSQL_CMD="mysql -h127.0.0.1 -uroot -p${DBDEPLOYER_ROOT_PASS} -P3306"

echo -n "Waiting for MySQL on port 3306..."
MAX_WAIT=60
COUNT=0
while ! ${MYSQL_CMD} -e "SELECT 1" >/dev/null 2>&1; do
    if [ $COUNT -ge $MAX_WAIT ]; then
        echo " TIMEOUT"
        exit 1
    fi
    echo -n "."
    sleep 1
    COUNT=$((COUNT + 1))
done
echo " OK"

ROOT_PASSWORD="${ROOT_PASSWORD:-default_password}"
INFRA="${INFRA:-infra-dbdeployer-mysql56-single}"

${MYSQL_CMD} <<SQL
SET SQL_LOG_BIN=0;

DELETE FROM mysql.user WHERE User='';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY '${ROOT_PASSWORD}' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}' WITH GRANT OPTION;
GRANT USAGE ON *.* TO 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' IDENTIFIED BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%' IDENTIFIED BY 'testuser';
-- MySQL 5.6 limits usernames to 16 chars, so '${INFRA}' is documented here but intentionally disabled.
-- GRANT ALL PRIVILEGES ON \`%test%\`.* TO '${INFRA}'@'%' IDENTIFIED BY '${INFRA}';
GRANT ALL PRIVILEGES ON *.* TO 'ssluser'@'%' IDENTIFIED BY 'ssluser' REQUIRE SSL;

CREATE DATABASE IF NOT EXISTS sysbench;
CREATE DATABASE IF NOT EXISTS test;
CREATE DATABASE IF NOT EXISTS t1;
CREATE DATABASE IF NOT EXISTS jdbc_test;

GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest1'@'%' IDENTIFIED BY 'sbtest1';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest1'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest1'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest1'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest2'@'%' IDENTIFIED BY 'sbtest2';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest2'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest2'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest2'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest3'@'%' IDENTIFIED BY 'sbtest3';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest3'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest3'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest3'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest4'@'%' IDENTIFIED BY 'sbtest4';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest4'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest4'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest4'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest7'@'%' IDENTIFIED BY 'sbtest7';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest7'@'%';
GRANT ALL PRIVILEGES ON sysbench.* TO 'sbtest8'@'%' IDENTIFIED BY 'sbtest8';
GRANT ALL PRIVILEGES ON test.* TO 'sbtest8'@'%';
GRANT ALL PRIVILEGES ON t1.* TO 'sbtest8'@'%';
GRANT ALL PRIVILEGES ON jdbc_test.* TO 'sbtest8'@'%';

FLUSH PRIVILEGES;
SQL

cp /root/certs/ca.pem "${SANDBOX_DIR}/data/ca.pem"
cp /root/certs/server-cert.pem "${SANDBOX_DIR}/data/server-cert.pem"
cp /root/certs/server-key.pem "${SANDBOX_DIR}/data/server-key.pem"

touch /tmp/dbdeployer_ready

echo "========================================================================"
echo "dbdeployer MySQL 5.6 single sandbox is ready on port 3306."
echo "========================================================================"

exec sleep infinity
