#!/bin/bash

. constants

# check if all required env vars are set
if [ -z "${INFRA}" ]; then
    echo "INFRA is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${HOST_IP}" ]; then
    echo "HOST_IP is empty, please check env vars passed to: " ${0}
    exit 1
elif [ -z "${USE_SSL}" ]; then
    echo "USE_SSL is empty, please check env vars passed to: " ${0}
    exit 1
fi

echo -n "[$(date)] Configuring replication: mysql1(source)=>mysql2(replica)=>proxysql=>mysql3(replica) ..."
mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e " \
STOP SLAVE; \
RESET SLAVE ALL;  \
CHANGE MASTER TO MASTER_HOST='${HOST_IP}', MASTER_PORT=6033, MASTER_USER='repl_casc',MASTER_PASSWORD='repl_casc',MASTER_AUTO_POSITION=1,MASTER_SSL=${USE_SSL}; \
START SLAVE; \
" 2>&1 | grep -vP "mysql: .?Warning"

RC=1

WAITED=0
TIMEOUT_LIMIT=15

while [ $RC -eq 1 ]
do
  if [ $WAITED -gt $TIMEOUT_LIMIT ]
  then
    echo
    echo "[ERROR] Timeout of $TIMEOUT_LIMIT seconds reached while waiting for replication to be configured"
    exit 1
  fi
  sleep 1
  printf "."
  if [[ $(mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e 'SHOW SLAVE STATUS\G' 2>&1 | grep -vP "mysql: .?Warning" | grep 'Running: Yes' | wc -l) -eq 2 ]]; then
    RC=0
  fi
  WAITED=$((WAITED+1))
done

echo " got $(mysql -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e 'SHOW SLAVE STATUS\G' 2>/dev/null | grep 'Slave_IO_State' | awk '{ $1=$1; print }')"

echo ' done.'
