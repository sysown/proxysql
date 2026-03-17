#!/bin/bash


[[ $(mysql --skip-ssl-verify-server-cert -h 2>&1) =~ skip-ssl-verify-server-cert ]] || export SSLOPT=--skip-ssl-verify-server-cert

echo -n "Waiting for 'mysql1.${INFRA}' ..."
while [[ ! $(mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql1.${INFRA}' ..."
mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
SET GLOBAL READ_ONLY=0; \
" 2>&1 | grep -vP 'mysql: .?Warning'
echo ' done.'

echo -n "Waiting for 'mysql2.${INFRA}' ..."
while [[ ! $(mysql ${SSLOPT} -h mysql2.${INFRA} -P 3306 -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h mysql2.${INFRA} -P 3306 -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql2.${INFRA}' ..."
mysql ${SSLOPT} -h mysql2.${INFRA} -P 3306 -uroot -proot -e " \
SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='mysql1.${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION = 1; \
START SLAVE; \
" 2>&1 | grep -vP 'mysql: .?Warning'
echo ' done.'

echo -n "Waiting for 'mysql3.${INFRA}' ..."
while [[ ! $(mysql ${SSLOPT} -h mysql3.${INFRA} -P 3306 -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h mysql3.${INFRA} -P 3306 -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql3.${INFRA}' ..."
mysql ${SSLOPT} -h mysql3.${INFRA} -P 3306 -uroot -proot -e " \
SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='mysql1.${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION = 1; \
START SLAVE; \
" 2>&1 | grep -vP 'mysql: .?Warning'
echo ' done.'


echo -n "Waiting for '${INFRA}' cluster ..."
while [[ ! $(mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e 'SHOW MASTER STATUS;' 2>&1 | grep -vP 'mysql: .?Warning' | wc -l) -eq 2 ]]; do echo -n '.'; sleep 1; done;
while [[ ! $(mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e 'SHOW SLAVE HOSTS;' 2>&1 | grep -vP 'mysql: .?Warning' | wc -l) -eq 3 ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h mysql2.${INFRA} -P 3306 -uroot -proot -e 'SHOW SLAVE STATUS\G' 2>&1 | grep -vP 'mysql: .?Warning' | grep 'Slave_IO_State' | awk '{ $1=$1; print }')"

echo -n "Configuring '${INFRA}' cluster ..."
mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
DROP USER IF EXISTS monitor@'%'; \
CREATE USER monitor@'%' IDENTIFIED WITH 'mysql_native_password' BY 'monitor';
GRANT usage,replication client on *.* to monitor@'%'; \

DROP USER IF EXISTS user@'%'; \
CREATE USER user@'%' IDENTIFIED WITH 'mysql_native_password' BY 'user'; \
GRANT all on *.* to user@'%'; \

DROP USER IF EXISTS testuser@'%'; \
CREATE USER testuser@'%' IDENTIFIED WITH 'mysql_native_password' BY 'testuser'; \
GRANT all on \`%test%\`.* to testuser@'%'; \

DROP USER IF EXISTS ssluser@'%'; \
CREATE USER ssluser@'%' IDENTIFIED WITH 'mysql_native_password' BY 'ssluser' REQUIRE SSL; \
GRANT all on *.* to ssluser@'%'; \

DROP USER IF EXISTS '${INFRA}'@'%'; \
CREATE USER '${INFRA}'@'%' IDENTIFIED WITH 'mysql_native_password' BY '${INFRA}'; \
GRANT all on \`%test%\`.* to '${INFRA}'@'%'; \
" 2>&1 | grep -vP 'mysql: .?Warning'

mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
DROP DATABASE IF EXISTS sysbench; \
CREATE DATABASE sysbench; \
DROP DATABASE IF EXISTS jdbc_test; \
CREATE DATABASE jdbc_test; \
CREATE TABLE jdbc_test.ts_test ( ts datetime DEFAULT NULL ); \
" 2>&1 | grep -vP 'mysql: .?Warning'

for MYUSER in sbtest7 sbtest8 ; do
	mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
	DROP USER IF EXISTS ${MYUSER}@'%'; \
	CREATE USER ${MYUSER}@'%' IDENTIFIED WITH 'mysql_native_password' BY '${MYUSER}'; \
	GRANT ALL ON *.* TO ${MYUSER}@'%'; \
	" 2>&1 | grep -vP 'mysql: .?Warning'

	for MYDB in sysbench test t1 jdbc_test ; do
		mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
		GRANT ALL ON ${MYDB}.* TO ${MYUSER}@'%'; \
		" 2>&1 | grep -vP 'mysql: .?Warning'
	done
done

mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
DROP USER IF EXISTS binlog@'%'; \
CREATE USER binlog@'%' IDENTIFIED WITH 'mysql_native_password' BY 'binlog'; \
GRANT usage, replication client, replication slave on *.* to binlog@'%'; \
" 2>&1 | grep -vP 'mysql: .?Warning'

mysql ${SSLOPT} -h mysql1.${INFRA} -P 3306 -uroot -proot -e " \
FLUSH PRIVILEGES; \
" 2>&1 | grep -vP 'mysql: .?Warning'

echo ' done.'
