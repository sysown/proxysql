#!/bin/bash

## inspired by Percona clustercheck.sh
if [ "$1" = '-h' -o "$1" = '--help'  -o -z "$1" ]; then
  echo "Usage: $0 <hostname> <port> <hostgroup_id> <log_file>" && exit 0
fi
if [ $# -lt 3 ]; then
  echo "Invalid number of arguments"
  echo "Usage: $0 <hostname> <port> <hostgroup_id> <log_file>" && exit 1
fi

PROXYSQL_USERNAME="admin"
PROXYSQL_PASSWORD="admin"
PROXYSQL_HOSTNAME="${1}"
PROXYSQL_PORT="${2}"
HOSTGROUP_ID="${3}"
ERR_FILE="${4:-/dev/null}"
#Timeout exists for instances where mysqld may be hung
TIMEOUT=10

PROXYSQL_CMDLINE="mysql -u$PROXYSQL_USERNAME -p$PROXYSQL_PASSWORD -h $PROXYSQL_HOSTNAME -P $PROXYSQL_PORT -Ne"
MYSQL_CREDENTIALS=$($PROXYSQL_CMDLINE "SELECT variable_value FROM global_variables WHERE variable_name IN ('mysql-monitor_username','mysql-monitor_password') ORDER BY variable_name")
MYSQL_USERNAME=$(echo $MYSQL_CREDENTIALS | awk '{print $1}')
MYSQL_PASSWORD=$(echo $MYSQL_CREDENTIALS | awk '{print $2}')
#echo $MYSQL_CREDENTIALS
#echo $MYSQL_USERNAME $MYSQL_PASSWORD
MYSQL_CMDLINE="timeout $TIMEOUT mysql -nNE -u$MYSQL_USERNAME -p$MYSQL_PASSWORD "

$PROXYSQL_CMDLINE "SELECT hostname,port,status FROM mysql_servers WHERE hostgroup_id='$HOSTGROUP_ID' AND status<>'OFFLINE_HARD'" | while read server port stat
do
  WSREP_STATUS=$($MYSQL_CMDLINE -h $server -P $port -e "SHOW STATUS LIKE 'wsrep_local_state'" 2>>${ERR_FILE} | tail -1 2>>${ERR_FILE})
  echo `date` Check server $server:$port , status $stat , wsrep_local_state $WSREP_STATUS >> ${ERR_FILE}
  if [ "${WSREP_STATUS}" = "4" -a "$stat" != "ONLINE" ] ; then
    echo `date` Changing server $server:$port to status ONLINE >> ${ERR_FILE}
    $PROXYSQL_CMDLINE "UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=$HOSTGROUP_ID AND hostname='$server' AND port='$port'; LOAD MYSQL SERVERS TO RUNTIME;" 2>> ${ERR_FILE}
  elif [ "${WSREP_STATUS}" != "4" -a "$stat" = "ONLINE" ] ; then
    echo `date` Changing server $server:$port to status OFFLINE_SOFT >> ${ERR_FILE}
    $PROXYSQL_CMDLINE "UPDATE mysql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=$HOSTGROUP_ID AND hostname='$server' AND port='$port'; LOAD MYSQL SERVERS TO RUNTIME;" 2>> ${ERR_FILE}
  fi
done
exit 0
