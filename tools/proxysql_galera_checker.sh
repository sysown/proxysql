#!/bin/bash

## inspired by Percona clustercheck.sh

set -u -e -o pipefail

PATH=$PATH:/sbin

# CHANGE THOSE
PROXYSQL_USERNAME='admin'
PROXYSQL_PASSWORD='admin'
PROXYSQL_HOSTNAME='localhost'
PROXYSQL_PORT='6032'


# DO NOT CHANGE ANYTHING BELOW
readonly GALERA_IN_SYNC_STATE=4
readonly GALERA_IS_ONLINE='ONLINE'
readonly GALERA_IS_OFFLINE_SOFT='OFFLINE_SOFT'


function usage()
{
   cat <<EOF

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

function log ()
{
   echo "$(date)" "${@}" >> "${ERR_FILE}"
}

function flag_to_reload ()
{
   echo '1' >"${RELOAD_CHECK_FILE}"
}

function clear_reload_flag ()
{
   test -f "${RELOAD_CHECK_FILE}" || return
   rm -f "${RELOAD_CHECK_FILE}"
}

function is_in_sync ()
{
   [ $# -eq 1 ] || { echo "${FUNCNAME[0]}: invalid parameters!"; exit 1; }
   [ "${1}" == "${GALERA_IN_SYNC_STATE}" ] || return 1
}

function is_online ()
{
   [ $# -eq 1 ] || { echo "${FUNCNAME[0]}: invalid parameters!"; exit 1; }
   [ "${1,,}" == "${GALERA_IS_ONLINE,,}" ] || return 1
}

function is_offline_soft ()
{
   [ $# -eq 1 ] || { echo "${FUNCNAME[0]}: invalid parameters!"; exit 1; }
   [ "${1,,}" == "${GALERA_IS_OFFLINE_SOFT,,}" ] || return 1
}

function is_writer_also_reader ()
{
   [ "${WRITER_IS_READER}" == "1" ] || return 1
   return 0
}

function proxysql_cmd ()
{
   env "MYSQL_PWD=${PROXYSQL_PASSWORD}" "${PROXYSQL_CMDLINE[@]}" "${@}"
}

function mysql_cmd ()
{
   local SERVER="${1}"
   local PORT="${2}"
   shift 2

   env "MYSQL_PWD=${MYSQL_PASSWORD}" "${MYSQL_CMDLINE[@]}" -h "${SERVER}" -P "${PORT}" -e "${@}"
}

function get_galera_state ()
{
   [ $# -eq 2 ] || { echo "${FUNCNAME[0]}: invalid parameters!"; exit 1; }
   [ ! -z "${1}" ] || { echo "${FUNCNAME[0]}: server-parameter is invalid!"; exit 1; }
   [ ! -z "${2}" ] || { echo "${FUNCNAME[0]}: port-parameter is invalid!"; exit 1; }

   local QUERY="SHOW STATUS LIKE 'wsrep_local_state'" RESULT=''

   if ! RESULT="$(mysql_cmd "${1}" "${2}" "${QUERY}" -E 2>> "${ERR_FILE}"| tail -1)"; then
      log "Failure retrieving 'wsrep_local_state' from '${1}'!"
      log "Result: ${RESULT}"
      exit 1
   fi

   if ! [[ "${RESULT}" =~ ^[[:digit:]]+$ ]]; then
      log "Found invalid 'wsrep_local_state' for '${1}': '${RESULT}'"
      exit 1
   fi

   echo "${RESULT}"
}

# DEFAULTS
HOSTGROUP_WRITER_ID="${1}"
HOSTGROUP_READER_ID="${2:--1}"
NUMBER_WRITERS="${3:-0}"
WRITER_IS_READER="${4:-1}"
ERR_FILE="${5:-/dev/null}"
RELOAD_CHECK_FILE='/var/lib/proxysql/reload'

# Prevent duplicate execution
BASENAME="$(basename "${BASH_SOURCE[0]}")"

if pidof -x -o %PPID "${BASENAME}"; then
   log '###### Another process is already running. Abort! ######'
   exit 0
fi

echo '0' > ${RELOAD_CHECK_FILE}

if [ "$1" = '-h' ] \
   || [ "$1" = '--help' ] \
   || [ $# -lt 1 ] \
   || [ -z "${1}" ]; then
   usage
   exit 0
fi

if [ $# -gt 5 ]; then
   echo 'ERROR: Invalid number of arguments'
   usage
   exit 1
fi


if ! [[ $HOSTGROUP_WRITER_ID =~ ^[[:digit:]]+$ ]]; then
   echo 'ERROR: writer hostgroup_id is not an integer'
   usage
   exit 1
fi

if ! [[ $HOSTGROUP_READER_ID =~ ^[[:digit:]]+$ ]]; then
   echo 'ERROR: reader hostgroup_id is not an integer'
   usage
   exit 1
fi

if ! [[ $NUMBER_WRITERS =~ ^[[:digit:]]+$ ]] || [ "${NUMBER_WRITERS}" -lt 0 ]; then
   echo 'ERROR: The number of writers should either be 0 to enable all possible nodes ONLINE'
   echo '       or be larger than 0 to limit the number of writers'
   usage
   exit 1
fi

if ! [[ $WRITER_IS_READER =~ ^(0|1)$ ]]; then
   echo 'ERROR: Writers are readers requires a boolean argument (0|1)'
   usage
   exit 1
fi

# print information prior to a run if ${ERR_FILE} is defined
cat >> "${ERR_FILE}"  <<EOF
$(date) ##### ${BASENAME} SUMMARY #####
$(date) Hostgroup writers ${HOSTGROUP_WRITER_ID}
$(date) Hostgroup readers ${HOSTGROUP_READER_ID}
$(date) Number of writers ${NUMBER_WRITERS}
$(date) Writers are readers ${WRITER_IS_READER}
$(date) log file ${ERR_FILE}
EOF

#Timeout exists for instances where mysqld may be hung
TIMEOUT=10

declare -a MYSQL_SERVERS=()
declare -a SQL_QUERY=()

declare -a PROXYSQL_CMDLINE=(
   "mysql"
   '-u' "${PROXYSQL_USERNAME}"
   '-h' "${PROXYSQL_HOSTNAME}"
   '-P' "${PROXYSQL_PORT}"
   '--protocol=tcp'
   '-Nse'
)

function change_server_status()
{
   log "Changing server $1:$2:$3 to status $4. Reason: $5"
   proxysql_cmd "UPDATE mysql_servers set status = '${4}' WHERE hostgroup_id=${1} AND hostname='${2}' AND port=${3};" 2>> "${ERR_FILE}"
}

MYSQL_USERNAME="$(proxysql_cmd "SELECT variable_value FROM global_variables WHERE variable_name='mysql-monitor_username'")"
MYSQL_PASSWORD="$(proxysql_cmd "SELECT variable_value FROM global_variables WHERE variable_name='mysql-monitor_password'")"

declare -a MYSQL_CMDLINE=(
   'mysql' '-nNBL'
   "--user=${MYSQL_USERNAME}"
   "--connect-timeout=${TIMEOUT}"
)


#########################################################
# check the writer nodes
#
log '###### HANDLE WRITER NODES ######'
NUMBER_WRITERS_ONLINE=0

SQL_QUERY=(
   'SELECT hostgroup_id, hostname, port, status'
   'FROM mysql_servers'
   "WHERE hostgroup_id=$HOSTGROUP_WRITER_ID"
   "AND status <> 'OFFLINE_HARD'"
   'ORDER BY hostgroup_id, weight DESC, hostname, port'
)

# fetch list of mysql-servers for hostgroup $HOSTGROUP_WRITER_ID
if ! mapfile -t MYSQL_SERVERS < <(proxysql_cmd "${SQL_QUERY[*]}"); then
   log "Failure retrieving mysql_servers from ProxySQL for writer-nodes!"
   exit 1
fi

for SERVER_LINE in "${MYSQL_SERVERS[@]}"; do
   # extract mysql-server information
   if ! read -r hostgroup server port stat <<<"${SERVER_LINE}"; then
      log "Failure extracting MySQL server info from '${SERVER_LINE}'!"
      exit 1
   fi

   if [ -z "${hostgroup}" ] \
      || [ -z "${server}" ] \
      || [ -z "${port}" ] \
      || [ -z "${stat}" ]; then
      log "Incomplete server information (hg:${hostgroup}, server:${server}, port:${port}, stat:${stat})!"
      exit 1
   fi

   # retrieve the mysql-server's galera state
   WSREP_STATUS="$(get_galera_state "${server}" "${port}")"

   log "--> Checking WRITE server $hostgroup:$server:$port, current status ${stat}, wsrep_local_state $WSREP_STATUS"

   # we have to limit amount of writers, WSREP status OK, AND node is not marked ONLINE
   if [ "${NUMBER_WRITERS}" -gt 0 ] \
      && is_in_sync "${WSREP_STATUS}" \
      && is_online "${stat}"; then

      if [ "${NUMBER_WRITERS_ONLINE}" -lt "${NUMBER_WRITERS}" ]; then
         ((NUMBER_WRITERS_ONLINE++)) || true
         log "server $hostgroup:$server:$port is already ONLINE: ${NUMBER_WRITERS_ONLINE} of ${NUMBER_WRITERS} write nodes"
      else
         ((NUMBER_WRITERS_ONLINE++)) || true
         change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" 'OFFLINE_SOFT' "max write nodes reached (${NUMBER_WRITERS})"
         flag_to_reload;
      fi
   fi

   # WSREP status OK, but node is not marked ONLINE
   if is_in_sync "${WSREP_STATUS}" && ! is_online "${stat}"; then

      # we have to limit amount of writers
      if [ "${NUMBER_WRITERS}" -gt 0 ]; then

         if [ "${NUMBER_WRITERS_ONLINE}" -lt "${NUMBER_WRITERS}" ]; then
            ((NUMBER_WRITERS_ONLINE++)) || true
            change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" "ONLINE" "${NUMBER_WRITERS_ONLINE} of ${NUMBER_WRITERS} write nodes"
            flag_to_reload
         else
            ((NUMBER_WRITERS_ONLINE++)) || true
            if ! is_offline_soft "${stat}"; then
               change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" 'OFFLINE_SOFT' "max write nodes reached (${NUMBER_WRITERS})"
               flag_to_reload;
            else
               log "server $hostgroup:$server:$port is already OFFLINE_SOFT, max write nodes reached (${NUMBER_WRITERS})"
            fi
         fi
      # we do not have to limit
      elif [ "${NUMBER_WRITERS}" -eq 0 ]; then
         change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" 'ONLINE' 'Changed state, marking write node ONLINE'
         flag_to_reload;
      fi
   fi

   # WSREP status is not ok, but the node is marked online, we should put it offline
   if ! is_in_sync "${WSREP_STATUS}" && is_online "${stat}"; then
      change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" 'OFFLINE_SOFT' "WSREP status is ${WSREP_STATUS} which is not ok"
      flag_to_reload;
   elif ! is_in_sync "${WSREP_STATUS}" && is_offline_soft "${stat}"; then
      log "server $hostgroup:$server:$port is already OFFLINE_SOFT, WSREP status is ${WSREP_STATUS} which is not ok"
   fi
done

SQL_QUERY=(
   'SELECT count(*)'
   'FROM mysql_servers'
   "WHERE hostgroup_id IN ($HOSTGROUP_WRITER_ID)"
   "AND status = 'ONLINE'"
)

NUMBER_WRITERS_ONLINE="$(proxysql_cmd "${SQL_QUERY[*]}" 2>>"${ERR_FILE}" | tail -1 2>> "${ERR_FILE}")"

if ! [[ "${NUMBER_WRITERS_ONLINE}" =~ ^[[:digit:]]$ ]]; then
   log "Got invalid number-of-writers-online information: '${NUMBER_WRITERS_ONLINE}'"
   exit 1
fi


#########################################################
# check the reader nodes
#
NUMBER_READERS_ONLINE=0

if [ "${HOSTGROUP_READER_ID}" -ne -1 ]; then
   log '###### HANDLE READER NODES ######'

   declare -a READER_PROXYSQL_QUERY=()

   if is_writer_also_reader; then
      READER_PROXYSQL_QUERY=(
         "SELECT hostgroup_id, hostname, port, status, 'NULL'"
         'FROM mysql_servers'
         "WHERE hostgroup_id IN ($HOSTGROUP_READER_ID)"
         "AND status <> 'OFFLINE_HARD'"
         'ORDER BY weight DESC, hostname, port'
      )
   elif ! is_writer_also_reader; then
      # We will not try to change reader state of nodes that are writer ONLINE,
      # so what we do is we ORDER BY writer.status ASC because by accident ONLINE
      # is last in the line
      READER_PROXYSQL_QUERY=(
         'SELECT reader.hostgroup_id, reader.hostname, reader.port, reader.status, writer.status'
         'FROM mysql_servers as reader'
         'LEFT JOIN mysql_servers as writer'
         "ON writer.hostgroup_id=$HOSTGROUP_WRITER_ID"
         'AND writer.hostname=reader.hostname'
         'AND writer.port=reader.port'
         "WHERE reader.hostgroup_id=$HOSTGROUP_READER_ID"
         "AND reader.status <> 'OFFLINE_HARD'"
         'ORDER BY writer.status ASC, reader.weight DESC, reader.hostname, reader.port'
      )
   fi

   OFFLINE_READERS_FOUND=0

   if ! mapfile -t MYSQL_SERVERS < <(proxysql_cmd "${READER_PROXYSQL_QUERY[*]}"); then
      log "Failure retrieving mysql_servers from ProxySQL!"
      exit 1
   fi

   for SERVER in "${MYSQL_SERVERS[@]}"; do
      if ! read -r hostgroup server port stat writer_stat <<<"${SERVER}"; then
         log "Failure extracting MySQL server info from '${SERVER}'!"
         exit 1
      fi

      if [ -z "${hostgroup}" ] \
         || [ -z "${server}" ] \
         || [ -z "${port}" ] \
         || [ -z "${stat}" ] \
         || [ -z "${writer_stat}" ]; then
         log "Incomplete server information (hg:${hostgroup}, server:${server}, port:${port}, stat:${stat}, writer-stat:${writer_stat})!"
         exit 1
      fi

      WSREP_STATUS="$(get_galera_state "${server}" "${port}")"

      log "--> Checking READ server $hostgroup:$server:$port, current status ${stat}, wsrep_local_state $WSREP_STATUS"

      if ! is_writer_also_reader && is_online "${writer_stat}"; then
         if [ "${OFFLINE_READERS_FOUND}" -eq 0 ]; then
            if is_in_sync "${WSREP_STATUS}" && is_online "${stat}"; then
               log "server $hostgroup:$server:$port is already ONLINE, is also write node in ONLINE state, not enough non-ONLINE readers found"
            fi

            if is_in_sync "${WSREP_STATUS}" && ! is_online "${stat}"; then
               change_server_status "${HOSTGROUP_READER_ID}" "${server}" "${port}" 'ONLINE' 'marking ONLINE write node as read ONLINE state, not enough non-ONLINE readers found'
               flag_to_reload;
            fi
         else
            if is_in_sync "${WSREP_STATUS}" && is_online "${stat}"; then
               change_server_status "${HOSTGROUP_READER_ID}" "${server}" "${port}" 'OFFLINE_SOFT' 'making ONLINE writer node as read OFFLINE_SOFT as well because writers should not be readers'
               flag_to_reload;
            fi

            if is_in_sync "${WSREP_STATUS}" && ! is_online "${stat}"; then
               log "server $hostgroup:$server:$port is ${stat}, keeping node in ${stat} is a writer ONLINE and it's preferred not to have writers as readers"
            fi
         fi
      else
         if is_in_sync "${WSREP_STATUS}" && is_online "${stat}"; then
            log "server $hostgroup:$server:$port is already ONLINE"
            ((OFFLINE_READERS_FOUND++)) || true
         fi

         # WSREP status OK, but node is not marked ONLINE
         if is_in_sync "${WSREP_STATUS}" && ! is_online "${stat}"; then
            change_server_status "${HOSTGROUP_READER_ID}" "${server}" "${port}" 'ONLINE' 'changed state, making read node ONLINE'
            flag_to_reload;
            ((OFFLINE_READERS_FOUND++)) || true
         fi
      fi

      # WSREP status is not ok, but the node is marked online, we should put it offline
      if ! is_in_sync "${WSREP_STATUS}" && is_online "${stat}"; then
         change_server_status "${HOSTGROUP_READER_ID}" "${server}" "${port}" 'OFFLINE_SOFT' "WSREP status is ${WSREP_STATUS} which is not ok"
         flag_to_reload;
      elif ! is_in_sync "${WSREP_STATUS}" && is_offline_soft "${stat}"; then
         log "server $hostgroup:$server:$port is already OFFLINE_SOFT, WSREP status is ${WSREP_STATUS} which is not ok"
      fi
   done

   NUMBER_READERS_ONLINE="$(proxysql_cmd "SELECT count(*) FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_READER_ID) AND status = 'ONLINE'" 2>>"${ERR_FILE}"| tail -1 2>>"${ERR_FILE}")"

   if ! [[ "${NUMBER_READERS_ONLINE}" =~ ^[[:digit:]]$ ]]; then
      log "Got invalid number-of-readers-online information: '${NUMBER_READERS_ONLINE}'"
      exit 1
   fi
fi

log '###### SUMMARY ######'
log "--> Number of writers that are 'ONLINE': ${NUMBER_WRITERS_ONLINE} : hostgroup: ${HOSTGROUP_WRITER_ID}"

if [ "${HOSTGROUP_READER_ID}" -ne -1 ]; then
  log "--> Number of readers that are 'ONLINE': ${NUMBER_READERS_ONLINE} : hostgroup: ${HOSTGROUP_READER_ID}"
fi

cnt=0
# We don't have any writers... alert, try to bring some online!
# This includes bringing a DONOR online
if [ "${NUMBER_WRITERS_ONLINE}" -eq 0 ]; then
   log '###### TRYING TO FIX MISSING WRITERS ######'
   log "No writers found, Trying to enable last available node of the cluster (in Donor/Desync state)"

   if ! mapfile -t MYSQL_SERVERS < <(proxysql_cmd "SELECT hostgroup_id, hostname, port, status FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_WRITER_ID) AND status <> 'OFFLINE_HARD'"); then
      log "Failure retrieving mysql_servers from ProxySQL!"
      exit 1
   fi

   for SERVER in "${MYSQL_SERVERS[@]}"; do
      if ! read -r hostgroup server port stat <<<"${SERVER}"; then
         log "Failure extracting MySQL server info from '${SERVER}'!"
         exit 1
      fi

      if [ -z "${hostgroup}" ] \
         || [ -z "${server}" ] \
         || [ -z "${port}" ] \
         || [ -z "${stat}" ]; then
         log "Incomplete server information (hg:${hostgroup}, server:${server}, port:${port}, stat:${stat})!"
         exit 1
      fi

      safety_cnt=0

      while [ "${cnt}" -le "${NUMBER_WRITERS}" ] && [ "${safety_cnt}" -lt 5 ]; do
         WSREP_STATUS="$(get_galera_state "${server}" "${port}")"

         log "Check server $hostgroup:$server:$port for only available node in DONOR state, status ${stat}, wsrep_local_state $WSREP_STATUS"

         # if we are on Donor/Desync an not online in mysql_servers -> proceed
         if [ "${WSREP_STATUS}" == '2' ] && ! is_online "${stat}"; then
            PROXY_RUNTIME_STATUS="$(proxysql_cmd "SELECT status FROM runtime_mysql_servers WHERE hostname='${server}' AND port='${port}' AND hostgroup_id='${hostgroup}'")"

            # if we are not online in runtime_mysql_servers, proceed to change the server
            # status and reload mysql_servers
            if [ "${PROXY_RUNTIME_STATUS}" != 'ONLINE' ]; then
               change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" 'ONLINE' 'WSREP status is DESYNC/DONOR, as this is the only node we will put this one online'
               flag_to_reload;
               ((cnt++)) || true
            # otherwise (we are already ONLINE in runtime_mysql_servers) no need to reload
            # so let's just remove RELOAD_CHECK_FILE and update it to ONLINE in mysql_servers
            # (in case something would reload it)
            else
               clear_reload_flag;
               ((cnt++)) || true
               change_server_status "${HOSTGROUP_WRITER_ID}" "${server}" "${port}" 'ONLINE' 'WSREP status is DESYNC/DONOR, as this is the only node we will put this one online'
            fi
         fi
         ((safety_cnt++)) || true
      done
   done
fi

cnt=0
# We don't have any readers... alert, try to bring some online!

if [ "${HOSTGROUP_READER_ID}" -ne -1 ] && [ "${NUMBER_READERS_ONLINE}" -eq 0 ]; then
   log '###### TRYING TO FIX MISSING READERS ######'
   log '--> No readers found, Trying to enable last available node of the cluster (in Donor/Desync state) or pick the master'

   if ! mapfile -t MYSQL_SERVERS < <(proxysql_cmd "SELECT hostgroup_id, hostname, port, status FROM mysql_servers WHERE hostgroup_id IN ($HOSTGROUP_READER_ID) AND status <> 'OFFLINE_HARD'"); then
      log "Failure retrieving mysql_servers from ProxySQL!"
      exit 1
   fi

   for SERVER in "${MYSQL_SERVERS[@]}"; do
      if ! read -r hostgroup server port stat <<<"${SERVER}"; then
         log "Failure extracting MySQL server info from '${SERVER}'!"
         exit 1
      fi

      if [ -z "${hostgroup}" ] \
         || [ -z "${server}" ] \
         || [ -z "${port}" ] \
         || [ -z "${stat}" ]; then
         log "Incomplete server information (hg:${hostgroup}, server:${server}, port:${port}, stat:${stat})!"
         exit 1
      fi

      safety_cnt=0

      while [ "${cnt}" -eq 0 ] && [ "${safety_cnt}" -lt 5 ]; do
         WSREP_STATUS="$(get_galera_state "${server}" "${port}")"

         log "Check server $hostgroup:$server:$port for only available node in DONOR state, status ${stat} , wsrep_local_state $WSREP_STATUS"

         # if we are on Donor/Desync an not online in mysql_servers -> proceed
         if [ "${WSREP_STATUS}" == '2' ] && ! is_online "${stat}"; then
            PROXY_RUNTIME_STATUS="$(proxysql_cmd "SELECT status FROM runtime_mysql_servers WHERE hostname='${server}' AND port='${port}' AND hostgroup_id='${hostgroup}'")"
            # if we are not online in runtime_mysql_servers, proceed to change the server
            # status and reload mysql_servers
            if [ "${PROXY_RUNTIME_STATUS}" != 'ONLINE' ]; then
               change_server_status "${HOSTGROUP_READER_ID}" "${server}" "${port}" 'ONLINE' 'WSREP status is DESYNC/DONOR, as this is the only node we will put this one online'
               flag_to_reload
               ((cnt++)) || true
            # otherwise (we are already ONLINE in runtime_mysql_servers) no need to reload
            # so let's just remove RELOAD_CHECK_FILE and update it to ONLINE in mysql_servers
            # (in case something would reload it)
            else
               clear_reload_flag
               ((cnt++)) || true
               change_server_status "${HOSTGROUP_READER_ID}" "${server}" "${port}" 'ONLINE' 'WSREP status is DESYNC/DONOR, as this is the only node we will put this one online'
            fi
         fi
         ((safety_cnt++)) || true
      done
   done
fi


if [ "$(cat "${RELOAD_CHECK_FILE}")" == '1' ]; then
    log '###### Loading mysql_servers config into runtime ######'
    proxysql_cmd 'LOAD MYSQL SERVERS TO RUNTIME;' 2>> "${ERR_FILE}"
else
    log '###### Not loading mysql_servers, no change needed ######'
fi

exit 0
