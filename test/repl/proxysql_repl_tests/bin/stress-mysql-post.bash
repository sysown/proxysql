#!/bin/bash

. constants

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
_w=0; while [[ ! $(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
echo " got $(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql1' ..."


mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e "${set_bl_chk} SET GLOBAL READ_ONLY=0;" 2>&1 | grep -vP "mysql: .?Warning"
echo ' done.'

echo -n "Waiting for 'mysql2' ..."
_w=0; while [[ ! $(mysql -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
echo " got $(mysql -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql2' ..."
mysql -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e " \
STOP SLAVE; \
${set_bl_chk} SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='${MYSQL1_HOST}${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION=1; \
START SLAVE; \
" 2>&1 | grep -vP "mysql: .?Warning"
echo ' done.'

echo -n "Waiting for 'mysql3' ..."
_w=0; while [[ ! $(mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
echo " got $(mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql3' ..."
mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e " \
STOP SLAVE; \
${set_bl_chk} SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='${MYSQL1_HOST}${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION=1; \
START SLAVE; \
" 2>&1 | grep -vP "mysql: .?Warning"
echo ' done.'

echo -n "Waiting for 'mysql4' ..."
_w=0; while [[ ! $(mysql -h${MYSQL4_HOST}${INFRA} -P${MYSQL4_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
echo " got $(mysql -h${MYSQL4_HOST}${INFRA} -P${MYSQL4_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql4' ..."
mysql -h${MYSQL4_HOST}${INFRA} -P${MYSQL4_PORT} -uroot -proot -e " \
${set_bl_chk} SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='${MYSQL1_HOST}${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION=1; \
START SLAVE; \
" 2>&1 | grep -vP "mysql: .?Warning"
echo ' done.'

echo -n "Waiting for 'mysql5' ..."
_w=0; while [[ ! $(mysql -h${MYSQL5_HOST}${INFRA} -P${MYSQL5_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null) =~ version ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
echo " got $(mysql -h${MYSQL5_HOST}${INFRA} -P${MYSQL5_PORT} -uroot -proot -e 'SELECT version()\G' 2>/dev/null | grep version)"
echo -n "Configuring 'mysql5' ..."
mysql -h${MYSQL5_HOST}${INFRA} -P${MYSQL5_PORT} -uroot -proot -e " \
${set_bl_chk} SET GLOBAL READ_ONLY=1; \
RESET MASTER; \
CHANGE MASTER TO MASTER_HOST='${MYSQL1_HOST}${INFRA}',MASTER_USER='root',MASTER_PASSWORD='root',MASTER_AUTO_POSITION=1; \
START SLAVE; \
" 2>&1 | grep -vP "mysql: .?Warning"
echo ' done.'

echo -n "Waiting for 'mysql' cluster ..."
_w=0; while [[ ! $(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SHOW MASTER STATUS;' 2>&1 | grep -vP "mysql: .?Warning" | wc -l) -eq 2 ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
_w=0; while [[ ! $(mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e 'SHOW SLAVE HOSTS;' 2>&1 | grep -vP "mysql: .?Warning" | wc -l) -eq 5 ]]; do echo -n '.'; sleep 1; _w=$((_w+1)); [ $_w -ge ${REPL_WAIT_TIMEOUT:-60} ] && { echo " [ERROR: timeout after ${REPL_WAIT_TIMEOUT:-60}s waiting for readiness in stress-mysql-post.bash]" >&2; exit 1; }; done;
echo " got $(mysql -h${MYSQL2_HOST}${INFRA} -P${MYSQL2_PORT} -uroot -proot -e 'SHOW SLAVE STATUS\G' 2>/dev/null | grep 'Slave_IO_State' | awk '{ $1=$1; print }')"

echo -n "Configuring 'mysql' cluster users and schemas ..."
mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot < <(eval "echo \"$(cat ./conf/mysql/mysql1/${MYSQL_VERSION}/create_init_users.sql)\"") 2>&1 | grep -vP "mysql: .?Warning"
mysql -h${MYSQL1_HOST}${INFRA} -P${MYSQL1_PORT} -uroot -proot -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE IF NOT EXISTS sysbench;" 2>&1 | grep -vP "mysql: .?Warning"
echo ' done.'
