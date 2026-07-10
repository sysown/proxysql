#!/usr/bin/bash

if [ -z "${SCRIPTPATH}" ]; then
  export SCRIPTPATH=${PWD}
  source ../env.sh
else
  cd ${SCRIPTPATH}
fi

. constants

# export env vars from .env to the environment of subsequent commands
set -a
. .env

ro_mon_errs_cur=0
ro_mon_errs_prev=0

if [[ $1 == "5.6" || $1 == "5.7" || $1 == "8.0" ]]; then
  export MYSQL_VERSION=$1
elif [ -z "$1" ]; then
  export MYSQL_VERSION="5.7"
else
  echo "Wrong parameter! Usage: ./exec_monitor_test.sh \$1 \$2 \$3, where \$1 is MySQL version (5.6/5.7/8.0), \$2 is SSL option"
  res=1
  exit $res
fi

if [[ $2 == "no-ssl" ]]; then
  SSL="no-ssl"
elif [ -z "$2" ] || [[ $2 == "SSL" || $2 == "ssl" ]]; then
  SSL="ssl"
else
  echo "Wrong parameter! Usage: ./exec_monitor_test.sh \$1 \$2 \$3, where \$1 is MySQL version (5.6/5.7/8.0), \$2 is SSL option"
  res=1
  exit $res
fi


if [ -z "${WORKSPACE}" ]; then
    echo "WORKSPACE is empty, please check ../env.sh"
    res=1
    exit $res
elif [ -z "${INFRA_LOGS_PATH}" ]; then
    echo "INFRA_LOGS_PATH is empty, please check ../env.sh"
    res=1
    exit $res
fi

export REPL_INFRA_DATADIR=$INFRA_LOGS_PATH/shun_infra
export REPL_TESTS_PATH=${PWD}


export INFRA=shun_tests
mkdir -p $REPL_INFRA_DATADIR
mkdir -p $REPL_INFRA_DATADIR/proxysql

#-------------------------------------------------------------------------------
# function for starting test output
fn_echo_start_test() {
  echo ""
  echo "================================================================================"
  echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
  echo "TEST STARTED: MySQL"${MYSQL_VERSION} ${SSL_}
  echo "Replication chain: "$1
  echo "================================================================================"
}

#-------------------------------------------------------------------------------
# function for sysbench test run
fn_sysbench_run () {
	echo "[`date '+%Y-%m-%d %H:%M:%S'`] >>> Running sysbench test ..."

  # create logs directory
  logdir="${INFRA_LOGS_PATH}/${INFRA}/sysbench/${MYSQL_VERSION}_${SSL}_${DEBEZIUM}"
  mkdir -p "$logdir"
  chmod 777 "$logdir"

  # run sysbench oltp test, pass logs directory parameter
  ./bin/local-docker-benchmark.bash $logdir

  # wait some time while generated data being replicated
  sleep 3
}

#-------------------------------------------------------------------------------
# function for generated data comparison on all cluster nodes / debezium data check
fn_sysbench_check () {
  if [[ $1 == "debezium" ]]; then
    # run debezium data check
    ./bin/debezium-check.bash
  else
    # run sysbench data checksum
    ./bin/mysql-data-checksum.bash
  fi
}

#-------------------------------------------------------------------------------
# function for running proxysql monitoring issue test
fn_kill_primary_backend () {
  docker kill ${INFRA}_mysql1
}

#-------------------------------------------------------------------------------
# function for running proxysql monitoring issue test
fn_start_primary_backend () {
  docker start ${INFRA}_mysql1
}

#-------------------------------------------------------------------------------
# function for checking poryxsql monitoring issue test result
fn_monitoring_issue_check () {

  echo "================================================================================"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Checking mysql servers status in proxysql admin ..."
  echo "Results"
  echo "runtime_mysql_servers status:"
  mysql -t -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e " \
  SELECT hostgroup_id, hostname, port, status, use_ssl FROM runtime_mysql_servers;
  " 2>&1 | grep -vP "mysql: .?Warning"
  echo "mysql_server_ping_log errors grouped by mysql server and error:"
  mysql -t -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e " \
  SELECT hostname, port, ping_error, FROM_UNIXTIME(MIN(time_start_us)/1000000) min_ts, FROM_UNIXTIME(MAX(time_start_us)/1000000) max_ts, COUNT(*) cnt \
  FROM mysql_server_ping_log \
  WHERE ping_error IS NOT NULL \
  GROUP BY hostname, port, ping_error \
  ORDER BY 1,2,3,4;
  " 2>&1 | grep -vP "mysql: .?Warning"
  chk3=$(mysql -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} --skip-column-names -e "SELECT COUNT(*) FROM runtime_mysql_servers WHERE status<>'ONLINE';" 2>&1 | grep -vP "mysql: .?Warning")
  chk4=$(mysql -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} --skip-column-names -e "SELECT COUNT(*) FROM runtime_mysql_servers WHERE status='ONLINE';" 2>&1 | grep -vP "mysql: .?Warning")
  echo "================================================================================"

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Counting number of monitor_read_only errors in proxysql.log ..."
#  chk1=$(grep -a "monitor_read_only_thread(): \[ERROR\]" $REPL_INFRA_DATADIR/proxysql/proxysql.log | wc -l)
  chk2=$(grep -a "monitor_read_only_process_ready_tasks(): \[ERROR\]" $REPL_INFRA_DATADIR/proxysql/proxysql.log | wc -l)
#  echo "Number of monitor_read_only_thread errors:" ${chk1}
  echo "Number of monitor_read_only_process_ready_tasks errors:" ${chk2}
  echo "Previous number of monitor_read_only_process_ready_tasks errors:" ${1}
  echo "================================================================================"

  if [[ $2 == "final_check" ]]; then
    # run final  check
    echo "================================================================================"
    echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
    echo "TEST SUMMARY:"
    if [[ "${1}" == "${chk2}" ]]; then
      echo "MONITORING TEST PASSED: no indefinite loop for monitor_read_only_process_ready_tasks errors in proxysql.log"
      res=0
    elif [ "${chk2}" -gt "${1}" ]; then
      echo "MONITORING TEST FAILED: number of monitor_read_only_process_ready_tasks errors in proxysql.log is growing"
      res=1
    else
      echo "MONITORING TEST FAILED"
      res=1
    fi
    if [[ "${chk3}" == "0" ]] && [[ "${chk4}" == "4" ]]; then
      echo "SERVER STATUS TEST PASSED: all hostgroups-servers got back to online"
      res=0
    else
      echo "SERVER STATUS TEST FAILED: ${chk4} hostgroups-servers online, ${chk3} hostgroups-servers NOT online"
      res=1
    fi
    echo "================================================================================"
  fi

  return $chk2

}

#-------------------------------------------------------------------------------
# function for infrastucture destroy and proxysql shutdown
fn_stop () {

  # destroy docker infrastucture
  ./docker-compose-destroy.bash
  # wait after stopping previous Docker infra
  sleep 5

  # shutdown proxysql
  # ensure ProxySQL is stopped
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] >>> Ensure ProxySQL is stopped..."
  mysql -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e "PROXYSQL SHUTDOWN SLOW" 2>&1 | grep -vP "mysql: .?Warning" | grep -v 'Lost connection to MySQL' || true
  sleep 5

}

#-------------------------------------------------------------------------------
# function for proxysql infrastucture initialization and proxysql startup
fn_start () {

  # Start ProxySQL
  SECONDS=0
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] >>> Starting ProxySQL..."
  cd "$WORKSPACE/src"
  (./proxysql --idle-threads -f -c "$REPL_TESTS_PATH/conf/proxysql/proxysql.cnf" -D $REPL_INFRA_DATADIR/proxysql >> $REPL_INFRA_DATADIR/proxysql/proxysql.log 2>&1 ) &
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> ProxySQL start DONE in ${SECONDS}s"
  sleep 3 # give proxysql some time to start

  cd $REPL_TESTS_PATH

  # Clean old data and launch infra
  ./docker-compose-init.bash

}


#-------------------------------------------------------------------------------
# function for the specific infastructure test run: mysql version parameter must be set
fn_run_main_test () {

  export MYSQL_VERSION=$1
  export SSL_=$2
  if [[ "${SSL_}" == "ssl" ]] ; then
    export USE_SSL=1
    export HAVE_SSL="true"
    export REQUIRE_SSL=" REQUIRE SSL"
  else
    export USE_SSL=0
    export HAVE_SSL="false"
    export REQUIRE_SSL=""
  fi
  export DEBEZIUM=$3

  # initial cleanup
  fn_stop

  # initial startup
  fn_start

  fn_echo_start_test "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Replication config: mysql1(source)=>mysql2(replica), mysql1(source)=>mysql3(replica)"

  sleep 5
  fn_monitoring_issue_check ${ro_mon_errs_prev}
  ro_mon_errs_prev=$?

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Killing primary backend container ${INFRA}_mysql1..."
  fn_kill_primary_backend
  echo "waiting 60 seconds after shutdown..."
  sleep 60
  fn_monitoring_issue_check ${ro_mon_errs_prev}
  ro_mon_errs_prev=$?

  echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Starting primary backend container ${INFRA}_mysql1..."
  fn_start_primary_backend
  echo "waiting 30 seconds after startup..."
  sleep 30
  fn_monitoring_issue_check ${ro_mon_errs_prev}
  ro_mon_errs_prev=$?

  echo "waiting another 30 seconds..."
  sleep 30
  fn_monitoring_issue_check ${ro_mon_errs_prev} final_check
  ro_mon_errs_prev=$?

}

res=0

fn_run_main_test $MYSQL_VERSION $SSL

if [ "$3" != "no-shutdown" ]; then
  fn_stop
fi

exit $res
