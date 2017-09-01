#!/bin/bash
## inspired by Percona clustercheck.sh

# CHANGE THOSE
PROXYSQL_USERNAME="admin"
PROXYSQL_PASSWORD="admin"
PROXYSQL_HOSTNAME="localhost"
PROXYSQL_PORT="6032"
#

function usage()
{
  cat << EOF

Usage: $0 <hostgroup_id write> [hostgroup_id read] [number writers] [writers are readers 0|1] [log_file]

- HOSTGROUP WRITERS   (required)  (0..)   The hostgroup_id that contains nodes that will server 'writes'
- HOSTGROUP READERS   (optional)  (0..)   The hostgroup_id that contains nodes that will server 'reads'
- NUMBER WRITERS      (optional)  (0..)   Maximum number of write hostgroup_id node that can be marked ONLINE
                                          When 0 (default), all nodes can be marked ONLINE
- WRITERS ARE READERS (optional)  (0|1)   When 1 (default), ONLINE nodes in write hostgroup_id will prefer not
                                          to be ONLINE in read hostgroup_id
- LOG_FILE            (optional)  file    logfile where node state checks & changes are written to (verbose)


Notes about the mysql_servers in ProxySQL:

- WEIGHT           Hosts with a higher weight will be prefered to be put ONLINE
- NODE STATUS      * Nodes that are in status OFFLINE_HARD will not be checked nor will their status be changed
                   * SHUNNED nodes are not to be used with Galera based systems, they will be checked and status
                     will be changed to either ONLINE or OFFLINE_SOFT.


When no nodes were found to be in wsrep_local_state=4 (SYNCED) for either 
read or write nodes, then the script will try 5 times for each node to try 
to find nodes wsrep_local_state=4 (SYNCED) or wsrep_local_state=2 (DONOR/DESYNC)

This is to avoid $0 to mark all nodes as OFFLINE_SOFT

EOF
}


# DEFAULTS
HOSTGROUP_WRITER_ID="${1}"
HOSTGROUP_READER_ID="${2:--1}"
NUMBER_WRITERS="${3:-0}"
WRITER_IS_READER="${4:-1}"
ERR_FILE="${5:-/dev/null}"
RELOAD_CHECK_FILE="/var/lib/proxysql/reload"

echo "0" > ${RELOAD_CHECK_FILE}

if [ "$1" = '-h' -o "$1" = '--help'  -o -z "$1" ]
then
  usage
  exit 0
fi

test $HOSTGROUP_WRITER_ID -ge 0 &> /dev/null
if [ $? -ne 0 ]; then
  echo "ERROR: writer hostgroup_id is not an integer"
  usage
  exit 1
fi

test $HOSTGROUP_READER_ID -ge -1 &> /dev/null
if [ $? -ne 0 ]; then
  echo "ERROR: reader hostgroup_id is not an integer"
  usage
  exit 1
fi

if [ $# -lt 1 -o $# -gt 5 ]; then
  echo "ERROR: Invalid number of arguments"
  usage
  exit 1
fi

if [ $NUMBER_WRITERS -lt 0 ]; then
  echo "ERROR: The number of writers should either be 0 to enable all possible nodes ONLINE"
  echo "       or be larger than 0 to limit the number of writers"
  usage
  exit 1
fi

if [ $WRITER_IS_READER -ne 0 -a $WRITER_IS_READER -ne 1 ]; then
  echo "ERROR: Writers are readers requires a boolean argument (0|1)"
  usage
  exit 1
fi


# print information prior to a run if ${ERR_FILE} is defined 
echo "`date` ###### proxysql_galera_checker.sh SUMMARY ######" >> ${ERR_FILE}
echo "`date` Hostgroup writers $HOSTGROUP_WRITER_ID" >> ${ERR_FILE}
echo "`date` Hostgroup readers $HOSTGROUP_READER_ID" >> ${ERR_FILE}
echo "`date` Number of writers $NUMBER_WRITERS" >> ${ERR_FILE}
echo "`date` Writers are readers $WRITER_IS_READER" >> ${ERR_FILE}
echo "`date` log file $ERR_FILE" >> ${ERR_FILE}

#Timeout exists for instances where mysqld may be hung
TIMEOUT=10

PROXYSQL_CMDLINE="env MYSQL_PWD=$PROXYSQL_PASSWORD mysql -u$PROXYSQL_USERNAME -h $PROXYSQL_HOSTNAME -P $PROXYSQL_PORT --protocol=tcp -Nse"
MYSQL_CREDENTIALS=$($PROXYSQL_CMDLINE "SELECT variable_value FROM global_variables WHERE variable_name IN ('mysql-monitor_username','mysql-monitor_password') ORDER BY variable_name DESC")
MYSQL_USERNAME=$(echo $MYSQL_CREDENTIALS | awk '{print $1}')
MYSQL_PASSWORD=$(echo $MYSQL_CREDENTIALS | awk '{print $2}')
MYSQL_CMDLINE="env MYSQL_PWD=$MYSQL_PASSWORD timeout $TIMEOUT mysql -nNE -u$MYSQL_USERNAME"


function change_server_status() {
  echo "`date` Changing server $1:$2:$3 to status $4. Reason: $5" >> ${ERR_FILE}
  $PROXYSQL_CMDLINE "UPDATE mysql_servers set status = '$4' WHERE hostgroup_id = $1 AND hostname = '$2' AND port = $3;" 2>> ${ERR_FILE}
}


echo "`date` ###### HANDLE WRITER NODES ######" >> ${ERR_FILE}
NUMBER_WRITERS_ONLINE=0
$PROXYSQL_CMDLINE "SELECT hostgroup_id, hostname, port, status FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_WRITER_ID) AND status <> 'OFFLINE_HARD' ORDER BY hostgroup_id, weight DESC, hostname, port" | while read hostgroup server port stat
do
  WSREP_STATUS=$($MYSQL_CMDLINE -h $server -P $port -e "SHOW STATUS LIKE 'wsrep_local_state'" 2>>${ERR_FILE}| tail -1 2>>${ERR_FILE})

  echo "`date` --> Checking WRITE server $hostgroup:$server:$port, current status $stat, wsrep_local_state $WSREP_STATUS" >> ${ERR_FILE}

  # we have to limit amount of writers, WSREP status OK, AND node is not marked ONLINE
  if [ $NUMBER_WRITERS -gt 0 -a "${WSREP_STATUS}" = "4" -a "$stat" == "ONLINE" ] ; then
      if [ $NUMBER_WRITERS_ONLINE -lt $NUMBER_WRITERS ]; then
        NUMBER_WRITERS_ONLINE=$(( $NUMBER_WRITERS_ONLINE + 1 ))
        echo "`date` server $hostgroup:$server:$port is already ONLINE: ${NUMBER_WRITERS_ONLINE} of ${NUMBER_WRITERS} write nodes" >> ${ERR_FILE}
      else
        NUMBER_WRITERS_ONLINE=$(( $NUMBER_WRITERS_ONLINE + 1 ))
        change_server_status $HOSTGROUP_WRITER_ID "$server" $port "OFFLINE_SOFT" "max write nodes reached (${NUMBER_WRITERS})"
        echo "1" > ${RELOAD_CHECK_FILE}

      fi
  fi

  # WSREP status OK, but node is not marked ONLINE
  if [ "${WSREP_STATUS}" = "4" -a "$stat" != "ONLINE" ] ; then
    # we have to limit amount of writers
    if [ $NUMBER_WRITERS -gt 0 ] ; then
      if [ $NUMBER_WRITERS_ONLINE -lt $NUMBER_WRITERS ]; then
        NUMBER_WRITERS_ONLINE=$(( $NUMBER_WRITERS_ONLINE + 1 ))
        change_server_status $HOSTGROUP_WRITER_ID "$server" $port "ONLINE" "{NUMBER_WRITERS_ONLINE} of ${NUMBER_WRITERS} write nodes"
        echo "1" > ${RELOAD_CHECK_FILE}
      else
        NUMBER_WRITERS_ONLINE=$(( $NUMBER_WRITERS_ONLINE + 1 ))
        if [ "$stat" != "OFFLINE_SOFT" ]; then
          change_server_status $HOSTGROUP_WRITER_ID "$server" $port "OFFLINE_SOFT" "max write nodes reached (${NUMBER_WRITERS})"
          echo "1" > ${RELOAD_CHECK_FILE}
        else
           echo "`date` server $hostgroup:$server:$port is already OFFLINE_SOFT, max write nodes reached (${NUMBER_WRITERS})" >> ${ERR_FILE}

        fi
      fi
    # we do not have to limit
    elif [ $NUMBER_WRITERS -eq 0 ] ; then
      change_server_status $HOSTGROUP_WRITER_ID "$server" $port "ONLINE" "Changed state, marking write node ONLINE"
      echo "1" > ${RELOAD_CHECK_FILE}
    fi
  fi

  # WSREP status is not ok, but the node is marked online, we should put it offline
  if [ "${WSREP_STATUS}" != "4" -a "$stat" = "ONLINE" ]; then
    change_server_status $HOSTGROUP_WRITER_ID "$server" $port "OFFLINE_SOFT" "WSREP status is ${WSREP_STATUS} which is not ok"
    echo "1" > ${RELOAD_CHECK_FILE}
  elif [ "${WSREP_STATUS}" != "4" -a "$stat" = "OFFLINE_SOFT" ]; then
    echo "`date` server $hostgroup:$server:$port is already OFFLINE_SOFT, WSREP status is ${WSREP_STATUS} which is not ok" >> ${ERR_FILE}
  fi

done

# NUMBER_WRITERS_ONLINE is lost after loop
NUMBER_WRITERS_ONLINE=$($PROXYSQL_CMDLINE "SELECT count(*) FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_WRITER_ID) AND status = 'ONLINE'" 2>>${ERR_FILE}| tail -1 2>>${ERR_FILE})


NUMBER_READERS_ONLINE=0
if [ ${HOSTGROUP_READER_ID} -ne -1 ]; then

  echo "`date` ###### HANDLE READER NODES ######" >> ${ERR_FILE}
  if [ $WRITER_IS_READER -eq 1 ]; then
    READER_PROXYSQL_QUERY="SELECT hostgroup_id, hostname, port, status, 'NULL' FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_READER_ID) AND status <> 'OFFLINE_HARD' ORDER BY weight DESC, hostname, port"
  elif [ $WRITER_IS_READER -eq 0 ]; then
    # We will not try to change reader state of nodes that are writer ONLINE, so what we do is we ORDER BY writer.status ASC because by accident ONLINE is last in the line
    READER_PROXYSQL_QUERY="SELECT reader.hostgroup_id,
         reader.hostname,
         reader.port,
         reader.status,
         writer.status
  FROM mysql_servers as reader
  LEFT JOIN mysql_servers as writer 
    ON writer.hostgroup_id = $HOSTGROUP_WRITER_ID 
    AND writer.hostname = reader.hostname 
    AND writer.port = reader.port
  WHERE reader.hostgroup_id = $HOSTGROUP_READER_ID
    AND reader.status <> 'OFFLINE_HARD'
  ORDER BY writer.status ASC,
           reader.weight DESC,
           reader.hostname,
           reader.port"
  fi

  OFFLINE_READERS_FOUND=0
  $PROXYSQL_CMDLINE "$READER_PROXYSQL_QUERY" | while read hostgroup server port stat writer_stat
  do
    WSREP_STATUS=$($MYSQL_CMDLINE -h $server -P $port -e "SHOW STATUS LIKE 'wsrep_local_state'" 2>>${ERR_FILE}| tail -1 2>>${ERR_FILE})

    echo "`date` --> Checking READ server $hostgroup:$server:$port, current status $stat, wsrep_local_state $WSREP_STATUS" >> ${ERR_FILE}

    if [ $WRITER_IS_READER -eq 0 -a "$writer_stat" == "ONLINE" ] ; then

      if [ $OFFLINE_READERS_FOUND -eq 0 ] ; then
        if [ "${WSREP_STATUS}" = "4" -a "$stat" == "ONLINE" ] ; then
          echo "`date` server $hostgroup:$server:$port is already ONLINE, is also write node in ONLINE state, not enough non-ONLINE readers found" >> ${ERR_FILE}
        fi

        if [ "${WSREP_STATUS}" = "4" -a "$stat" != "ONLINE" ] ; then
          change_server_status $HOSTGROUP_READER_ID "$server" $port "ONLINE" "marking ONLINE write node as read ONLINE state, not enough non-ONLINE readers found"
          echo "1" > ${RELOAD_CHECK_FILE}
        fi
      else
        if [ "${WSREP_STATUS}" = "4" -a "$stat" == "ONLINE" ] ; then
          change_server_status $HOSTGROUP_READER_ID "$server" $port "OFFLINE_SOFT" "making ONLINE writer node as read OFFLINE_SOFT as well because writers should not be readers"
          echo "1" > ${RELOAD_CHECK_FILE}
        fi

        if [ "${WSREP_STATUS}" = "4" -a "$stat" != "ONLINE" ] ; then
          echo "`date` server $hostgroup:$server:$port is $stat, keeping node in $stat is a writer ONLINE and it's preferred not to have writers as readers" >> ${ERR_FILE}
        fi
      fi
    else
      if [ "${WSREP_STATUS}" = "4" -a "$stat" == "ONLINE" ] ; then
        echo "`date` server $hostgroup:$server:$port is already ONLINE" >> ${ERR_FILE}
        OFFLINE_READERS_FOUND=$(( $OFFLINE_READERS_FOUND + 1 ))
      fi

      # WSREP status OK, but node is not marked ONLINE
      if [ "${WSREP_STATUS}" = "4" -a "$stat" != "ONLINE" ] ; then
        change_server_status $HOSTGROUP_READER_ID "$server" $port "ONLINE" "changed state, making read node ONLINE"
        echo "1" > ${RELOAD_CHECK_FILE}
        OFFLINE_READERS_FOUND=$(( $OFFLINE_READERS_FOUND + 1 ))
      fi
    fi

    # WSREP status is not ok, but the node is marked online, we should put it offline
    if [ "${WSREP_STATUS}" != "4" -a "$stat" = "ONLINE" ]; then
      change_server_status $HOSTGROUP_READER_ID "$server" $port "OFFLINE_SOFT" "WSREP status is ${WSREP_STATUS} which is not ok"
      echo "1" > ${RELOAD_CHECK_FILE}
    elif [ "${WSREP_STATUS}" != "4" -a "$stat" = "OFFLINE_SOFT" ]; then
      echo "`date` server $hostgroup:$server:$port is already OFFLINE_SOFT, WSREP status is ${WSREP_STATUS} which is not ok" >> ${ERR_FILE}
    fi
  done

  NUMBER_READERS_ONLINE=$($PROXYSQL_CMDLINE "SELECT count(*) FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_READER_ID) AND status = 'ONLINE'" 2>>${ERR_FILE}| tail -1 2>>${ERR_FILE})
fi

echo "`date` ###### SUMMARY ######" >> ${ERR_FILE}
echo "`date` --> Number of writers that are 'ONLINE': ${NUMBER_WRITERS_ONLINE} : hostgroup: ${HOSTGROUP_WRITER_ID}" >> ${ERR_FILE}
[ ${HOSTGROUP_READER_ID} -ne -1 ] && echo "`date` --> Number of readers that are 'ONLINE': ${NUMBER_READERS_ONLINE} : hostgroup: ${HOSTGROUP_READER_ID}" >> ${ERR_FILE}


cnt=0
# We don't have any writers... alert, try to bring some online!
# This includes bringing a DONOR online
if [ ${NUMBER_WRITERS_ONLINE} -eq 0 ]; then
  echo "`date` ###### TRYING TO FIX MISSING WRITERS ######"
  echo "`date` No writers found, Trying to enable last available node of the cluster (in Donor/Desync state)" >> ${ERR_FILE}
  $PROXYSQL_CMDLINE "SELECT hostgroup_id, hostname, port, status FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_WRITER_ID) AND status <> 'OFFLINE_HARD'" | while read hostgroup server port stat
  do
    safety_cnt=0
      while [ ${cnt} -le $NUMBER_WRITERS -a ${safety_cnt} -lt 5 ]
      do
        WSREP_STATUS=$($MYSQL_CMDLINE -h $server -P $port -e "SHOW STATUS LIKE 'wsrep_local_state'" 2>>${ERR_FILE} | tail -1 2>>${ERR_FILE})
        echo "`date` Check server $hostgroup:$server:$port for only available node in DONOR state, status $stat , wsrep_local_state $WSREP_STATUS" >> ${ERR_FILE}
        if [ "${WSREP_STATUS}" = "2" -a "$stat" != "ONLINE" ] # if we are on Donor/Desync an not online in mysql_servers -> proceed
        then
          PROXY_RUNTIME_STATUS=$($PROXYSQL_CMDLINE "SELECT status FROM runtime_mysql_servers WHERE hostname='${server}' AND port='${port}' AND hostgroup_id='${hostgroup}'")
          if [ "${PROXY_RUNTIME_STATUS}" != "ONLINE" ] # if we are not online in runtime_mysql_servers, proceed to change the server status and reload mysql_servers
          then
            change_server_status $HOSTGROUP_WRITER_ID "$server" $port "ONLINE" "WSREP status is DESYNC/DONOR, as this is the only node we will put this one online"
            echo "1" > ${RELOAD_CHECK_FILE}
            cnt=$(( $cnt + 1 ))
          else # otherwise (we are already ONLINE in runtime_mysql_servers) no need to reload so let's just remove RELOAD_CHECK_FILE and update it to ONLINE in mysql_servers (in case something would reload it)
            rm ${RELOAD_CHECK_FILE}
            cnt=$(( $cnt + 1 ))
            change_server_status $HOSTGROUP_WRITER_ID "$server" $port "ONLINE" "WSREP status is DESYNC/DONOR, as this is the only node we will put this one online"
          fi
        fi
        safety_cnt=$(( $safety_cnt + 1 ))
    done
  done
fi


cnt=0
# We don't have any readers... alert, try to bring some online!
if [  ${HOSTGROUP_READER_ID} -ne -1 -a ${NUMBER_READERS_ONLINE} -eq 0 ]; then
  echo "`date` ###### TRYING TO FIX MISSING READERS ######"
  echo "`date` --> No readers found, Trying to enable last available node of the cluster (in Donor/Desync state) or pick the master" >> ${ERR_FILE}
  $PROXYSQL_CMDLINE "SELECT hostgroup_id, hostname, port, status FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_READER_ID) AND status <> 'OFFLINE_HARD'" | while read hostgroup server port stat
  do
    safety_cnt=0
      while [ ${cnt} -eq 0 -a ${safety_cnt} -lt 5 ]
      do
        WSREP_STATUS=$($MYSQL_CMDLINE -h $server -P $port -e "SHOW STATUS LIKE 'wsrep_local_state'" 2>>${ERR_FILE} | tail -1 2>>${ERR_FILE})
        echo "`date` Check server $hostgroup:$server:$port for only available node in DONOR state, status $stat , wsrep_local_state $WSREP_STATUS" >> ${ERR_FILE}
        if [ "${WSREP_STATUS}" = "2" -a "$stat" != "ONLINE" ] # if we are on Donor/Desync an not online in mysql_servers -> proceed
        then
          PROXY_RUNTIME_STATUS=$($PROXYSQL_CMDLINE "SELECT status FROM runtime_mysql_servers WHERE hostname='${server}' AND port='${port}' AND hostgroup_id='${hostgroup}'")
          if [ "${PROXY_RUNTIME_STATUS}" != "ONLINE" ] # if we are not online in runtime_mysql_servers, proceed to change the server status and reload mysql_servers
          then
            change_server_status $HOSTGROUP_READER_ID "$server" $port "ONLINE" "WSREP status is DESYNC/DONOR, as this is the only node we will put this one online"
            echo "1" > ${RELOAD_CHECK_FILE}
            cnt=$(( $cnt + 1 ))
          else # otherwise (we are already ONLINE in runtime_mysql_servers) no need to reload so let's just remove RELOAD_CHECK_FILE and update it to ONLINE in mysql_servers (in case something would reload it)
            rm ${RELOAD_CHECK_FILE}
            cnt=$(( $cnt + 1 ))
            change_server_status $HOSTGROUP_READER_ID "$server" $port "ONLINE" "WSREP status is DESYNC/DONOR, as this is the only node we will put this one online"
          fi
        fi
        safety_cnt=$(( $safety_cnt + 1 ))
    done
  done
fi


if [ $(cat ${RELOAD_CHECK_FILE})  -ne 0 ] ; then
    echo "`date` ###### Loading mysql_servers config into runtime ######" >> ${ERR_FILE}
    $PROXYSQL_CMDLINE "LOAD MYSQL SERVERS TO RUNTIME;" 2>> ${ERR_FILE}
else
    echo "`date` ###### Not loading mysql_servers, no change needed ######" >> ${ERR_FILE}
fi


exit 0
