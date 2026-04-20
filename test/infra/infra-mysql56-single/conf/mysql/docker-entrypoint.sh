#!/bin/bash
set -e
set -o pipefail

DATADIR=/var/lib/mysql
MYSQL_BASE=/opt/mysql
MYSQLD_SAFE="${MYSQL_BASE}/bin/mysqld_safe"
MYSQL_INSTALL_DB="${MYSQL_BASE}/scripts/mysql_install_db"
MYSQL="${MYSQL_BASE}/bin/mysql"
MYSQLADMIN="${MYSQL_BASE}/bin/mysqladmin"
ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-root}"
INFRA_USER="${INFRA:-infra-mysql56-single}"

mkdir -p "${DATADIR}" /var/log/mysql
/usr/local/bin/configure_ssl.sh "${DATADIR}"
chown -R mysql:mysql "${DATADIR}" /var/log/mysql

if [ ! -d "${DATADIR}/mysql" ]; then
    su -s /bin/bash mysql -c "${MYSQL_INSTALL_DB} --user=mysql --basedir=${MYSQL_BASE} --datadir=${DATADIR}"

    su -s /bin/bash mysql -c "${MYSQLD_SAFE} --defaults-file=/etc/mysql/my.cnf --datadir=${DATADIR}" &

    echo -n "Initializing MySQL 5.6 data directory"
    MAX_WAIT=60
    COUNT=0
    until ${MYSQLADMIN} --protocol=socket --socket=${DATADIR}/mysql.sock -uroot ping >/dev/null 2>&1; do
        if [ $COUNT -ge $MAX_WAIT ]; then
            echo " TIMEOUT"
            exit 1
        fi
        echo -n "."
        sleep 1
        COUNT=$((COUNT + 1))
    done
    echo " OK"

    ${MYSQL} --protocol=socket --socket=${DATADIR}/mysql.sock -uroot <<SQL
SET SQL_LOG_BIN=0;
DELETE FROM mysql.user WHERE User='';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' IDENTIFIED BY '${ROOT_PASSWORD}' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY '${ROOT_PASSWORD}' WITH GRANT OPTION;
GRANT USAGE ON *.* TO 'monitor'@'%' IDENTIFIED BY 'monitor';
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' IDENTIFIED BY 'user';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%' IDENTIFIED BY 'testuser';
-- MySQL 5.6 limits usernames to 16 chars, so '${INFRA_USER}' is documented here but intentionally disabled.
-- GRANT ALL PRIVILEGES ON \`%test%\`.* TO '${INFRA_USER}'@'%' IDENTIFIED BY '${INFRA_USER}';
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

    ${MYSQLADMIN} --protocol=socket --socket=${DATADIR}/mysql.sock -uroot -p"${ROOT_PASSWORD}" shutdown
fi

exec su -s /bin/bash mysql -c "${MYSQLD_SAFE} --defaults-file=/etc/mysql/my.cnf --datadir=${DATADIR}"
