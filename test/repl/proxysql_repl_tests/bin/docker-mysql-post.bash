#!/bin/bash

. constants

[[ $(mysql --skip-ssl-verify-server-cert -h 2>&1) =~ skip-ssl-verify-server-cert ]] || export SSLOPT=--skip-ssl-verify-server-cert

# check if all required env vars are set
if [ -z "${INFRA}" ]; then
    echo "INFRA is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${MYSQL_VERSION}" ]; then
    echo "MYSQL_VERSION is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${USE_SSL}" ]; then
      echo "USE_SSL is empty, please check env vars passed to: " ${0}
      exit 1
elif [ -z "${HAVE_SSL}" ]; then
      echo "HAVE_SSL is empty, please check env vars passed to: " ${0}
      exit 1
fi

if [[ $1 == "no_binlog_checksum" ]]; then
  set_bl_chk="SET GLOBAL binlog_checksum='NONE';"
else
  set_bl_chk=""
fi

echo -n "Waiting for 'mysql1' ..."
while [[ ! $(mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql1' ..."


mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e "${set_bl_chk} SET GLOBAL READ_ONLY=0;" 2>&1 | grep -v "Using a password"
echo ' done.'

echo -n "Waiting for 'mysql2' ..."
while [[ ! $(mysql ${SSLOPT} -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql2' ..."
mysql ${SSLOPT} -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e " \
${set_bl_chk} SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='${MYSQL1_HOST}${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION=1; \
START SLAVE; \
" 2>&1 | grep -v "Using a password"
echo ' done.'

echo -n "Waiting for 'mysql3' ..."
while [[ ! $(mysql ${SSLOPT} -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql3' ..."
mysql ${SSLOPT} -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e " \
${set_bl_chk} SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='${MYSQL1_HOST}${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION=1; \
START SLAVE; \
" 2>&1 | grep -v "Using a password"
echo ' done.'


echo -n "Waiting for 'mysql' cluster ..."
while [[ ! $(mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SHOW MASTER STATUS;' 2>&1 | grep -v 'Using a password' | wc -l) -eq 2 ]]; do echo -n '.'; sleep 1; done;
while [[ ! $(mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SHOW SLAVE HOSTS;' 2>&1 | grep -v 'Using a password' | wc -l) -eq 3 ]]; do echo -n '.'; sleep 1; done;
echo " got $(mysql ${SSLOPT} -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e 'SHOW SLAVE STATUS\G' 2>/dev/null | grep 'Slave_IO_State' | awk '{ $1=$1; print }')"

echo -n "Configuring 'mysql' cluster users and schemas ..."
mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot < <(eval "echo \"$(cat ./conf/mysql/mysql1/${MYSQL_VERSION}/create_init_users.sql)\"") 2>&1 | grep -v 'Using a password'
mysql ${SSLOPT} -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE IF NOT EXISTS sysbench;" 2>&1 | grep -v "Using a password"
echo ' done.'
