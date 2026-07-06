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

if [[ -z ${WORKSPACE} || ! -f ${WORKPACE}/src/proxysql ]]; then
  export WORKSPACE=/var/lib/jenkins/scripts/infra-proxysql/proxysql/
fi

[[ $(mysql --skip-ssl-verify-server-cert -h 2>&1) =~ skip-ssl-verify-server-cert ]] || export SSLOPT=--skip-ssl-verify-server-cert

if [[ $1 == "5.6" || $1 == "5.7" || $1 == "8.0" ]]; then
  export MYSQL_VERSION=$1
elif [ -z "$1" ]; then
  export MYSQL_VERSION="5.7"
else
  echo "Wrong parameter! Usage: ./stress_repl_test.sh \$1 \$2 \$3, where \$1 is MySQL version (5.6/5.7/8.0), \$2 is SSL option, \$3 is debezium option "
  res=1
  exit $res
fi

if [[ $2 == "SSL" || $2 == "ssl" ]]; then
  SSL="ssl"
elif [ -z "$2" ] || [[ $2 == "no-ssl" ]]; then
  SSL="no-ssl"
else
  echo "Wrong parameter! Usage: ./stress_repl_test.sh \$1 \$2 \$3, where \$1 is MySQL version (5.6/5.7/8.0), \$2 is SSL option, \$3 is debezium option "
  res=1
  exit $res
fi

if [[ $3 == "debezium" ]]; then
  export DEBEZIUM=$3
elif [ -z "$3" ]; then
  DEBEZIUM=""
else
  echo "Wrong parameter! Usage: ./stress_repl_test.sh \$1 \$2 \$3, where \$1 is MySQL version (5.6/5.7/8.0), \$2 is SSL option, \$3 is debezium option"
  res=1
  exit $res
fi

if [ -z "${WORKSPACE}" ]; then
    echo "WORKSPACE is empty, please check ../env.sh"
    res=1
    exit $res
elif [ -z "${REPL_TESTS_PATH}" ]; then
    echo "REPL_TESTS_PATH is empty, please check ../env.sh"
    res=1
    exit $res
elif [ -z "${REPL_INFRA_DATADIR}" ]; then
    echo "REPL_INFRA_DATADIR is empty, please check ../env.sh"
    res=1
    exit $res
fi

export INFRA=${PWD##*/}
mkdir -p $REPL_INFRA_DATADIR
mkdir -p $REPL_INFRA_DATADIR/proxysql

#-------------------------------------------------------------------------------
# function for starting test output
fn_echo_start_test() {
  echo ""
  echo "================================================================================"
  echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
  echo "TEST STARTED: MySQL"${MYSQL_VERSION} ${SSL_} ${DEBEZIUM}
  echo "Replication chain: "$1
  echo "================================================================================"
}

#-------------------------------------------------------------------------------
# function for sysbench test run
fn_sysbench_run () {
	echo "[`date '+%Y-%m-%d %H:%M:%S'`] >>> Running sysbench test "$1"..."

  # create logs directory
  logdir="${INFRA_LOGS_PATH}/${INFRA}/sysbench/${MYSQL_VERSION}_${SSL}_${DEBEZIUM}"
  mkdir -p "$logdir"
  chmod 777 "$logdir"

  # run sysbench oltp test, pass logs directory parameter
  if [[ $1 == "writes-only" ]]; then
    ./bin/stress-writes-benchmark.bash $logdir
  else
    ./bin/stress-reads-benchmark.bash $logdir
  fi

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
    ./bin/stress-mysql-data-checksum.bash
  fi
}

#-------------------------------------------------------------------------------
# function for restarting replication
fn_restart_repl () {
  num=$(( (${1} % 5) + 1 ))

  echo Restarting replication on mysql3, mysql4, mysql5
  mysql ${SSLOPT} -h${MYSQL3_HOST}${INFRA} -P${MYSQL3_PORT} -uroot -proot -e "STOP SLAVE; START SLAVE;" 2>&1 | grep -v "Using a password"
  mysql ${SSLOPT} -h${MYSQL4_HOST}${INFRA} -P${MYSQL4_PORT} -uroot -proot -e "STOP SLAVE; START SLAVE;" 2>&1 | grep -v "Using a password"
  mysql ${SSLOPT} -h${MYSQL5_HOST}${INFRA} -P${MYSQL5_PORT} -uroot -proot -e "STOP SLAVE; START SLAVE;" 2>&1 | grep -v "Using a password"
  echo Running 1 update sbtest${num} ...
  mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYSQL_PORT} -uroot -proot sysbench -e "UPDATE sbtest${num} u JOIN (SELECT MIN(id) id FROM sbtest${num}) s USING (id) SET u.k=u.k+1;" 2>&1 | grep -v 'Using a password'

  sleep 3
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
  mysql ${SSLOPT} -h${PROXYSQL_HOST} -P${PROXYADM_PORT} -u${PROXYADM_USER} -p${PROXYADM_PWD} -e "PROXYSQL SHUTDOWN SLOW" 2>&1 | grep -v 'Using a password' | grep -v 'Lost connection to MySQL' || true
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

  # Clean old data and launch infra, pass 'no_binlog_checksum' if it's required
  ./stress-docker-compose-init.bash $1

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
  fn_start $4

  # array for the summary results
  results=()

  if [[ $4 == "initial_check" ]]; then
    # run Sysbench OLTP test on initial config

    if [[ ${DEBEZIUM} == "debezium" ]]; then
      fn_echo_start_test "initial config: mysql1(source)=>mysql2(replica), mysql1(source)=>mysql3(replica), mysql1(source) => debezium(replication stream)"
      ./bin/debezium-init-config.bash
    else
      fn_echo_start_test "initial config: mysql1(source)=>mysql2(replica), mysql1(source)=>mysql3(replica)"
    fi

    repl_chain="initial config: mysql1(source)=>mysql2(replica), mysql1(source)=>mysql3(replica)"
    fn_sysbench_run
    fn_sysbench_check
    if [ $? -ne 0 ]; then
      res=1
      results+=("$repl_chain FAILED")
    else
      results+=("$repl_chain passed")
    fi

    if [[ ${DEBEZIUM} == "debezium" ]]; then
      repl_chain="initial config: mysql1(source) => debezium(replication stream)"
      fn_sysbench_check debezium
      if [ $? -ne 0 ]; then
        res=1
        results+=("$repl_chain FAILED")
      else
        results+=("$repl_chain passed")
      fi
    fi

  fi

  # find local host IP in bridge docker network
  # in order to connect to ProxySQL from MySQL inside container
  export HOST_IP=$(docker network inspect bridge -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')

  #-------------------------------------------------------------------------------
  repl_chain="mysql1(source)=>proxysql=>mysql3/4/5(replicas)"
  fn_echo_start_test "$repl_chain"
  # configure replication: mysql1(source)=>proxysql=>mysql3(replica)
  ./bin/stress-proxy-repl-config.bash
  ./bin/stress-mysql-repl-config.bash
  # test replication: mysql1(source)=>proxysql=>mysql3(replica)

  fn_sysbench_run
  fn_sysbench_check
  if [ $? -ne 0 ]; then
    res=1
    results+=("$repl_chain read-write FAILED")
  else
    results+=("$repl_chain read-write passed")
  fi

  fn_sysbench_run write-only
  fn_sysbench_check
  if [ $? -ne 0 ]; then
    res=1
    results+=("$repl_chain write-only FAILED")
  else
    results+=("$repl_chain write-only passed")
  fi

  echo "[`date '+%Y-%m-%d %H:%M:%S'`] >>> Running replication restart test ..."
  repl_res=0
  for i in $(seq 1 10)
  do
    echo "[`date '+%Y-%m-%d %H:%M:%S'`] Run $i ..."
    fn_restart_repl $i
    fn_sysbench_check
    if [ $? -ne 0 ]; then
      res=1
      repl_res=1
      results+=("$repl_chain replication restart run $i FAILED")
    fi
  done
  if [ $repl_res -eq 0 ]; then
    results+=("$repl_chain 10 replication restarts passed")
  fi

  #-------------------------------------------------------------------------------
  repl_chain="mysql1(source)=>mysql2(replica)=>proxysql=>mysql3/4/5(replicas)"
  fn_echo_start_test "$repl_chain"
  # configure cascade replication: mysql1(source)=>mysql2(replica)=>proxysql=>mysql3(replica)
  ./bin/stress-proxy-repl-casc-config.bash
  ./bin/stress-mysql-repl-casc-config.bash
  # test replication: mysql1(source)=>mysql2(replica)=>proxysql=>mysql3(replica)

#  fn_sysbench_run
#  fn_sysbench_check
#  if [ $? -ne 0 ]; then
#    res=1
#    results+=("$repl_chain read-write FAILED")
#  else
#    results+=("$repl_chain read-write passed")
#  fi

  fn_sysbench_run write-only
  fn_sysbench_check
  if [ $? -ne 0 ]; then
    res=1
    results+=("$repl_chain write-only FAILED")
  else
    results+=("$repl_chain write-only passed")
  fi

  echo "[`date '+%Y-%m-%d %H:%M:%S'`] >>> Running replication restart test ..."
  repl_res=0
  for i in $(seq 1 10)
  do
    echo "[`date '+%Y-%m-%d %H:%M:%S'`] Run $i ..."
    fn_restart_repl $i
    fn_sysbench_check
    if [ $? -ne 0 ]; then
      res=1
      repl_res=1
      results+=("$repl_chain replication restart run $i FAILED")
    fi
  done
  if [ $repl_res -eq 0 ]; then
    results+=("$repl_chain 10 replication restarts passed")
  fi

  #-------------------------------------------------------------------------------
  if [[ ${DEBEZIUM} == "debezium" ]]; then
    repl_chain="mysql1(source)=>proxysql=>debezium(replication stream)"
    fn_echo_start_test "$repl_chain"
    # configure connection: mysql1(source)=>proxysql=>debezium(replication stream)
    ./bin/proxy-debezium-config.bash
    ./bin/debezium-repl-config.bash
    # test replication: mysql1(source)=>proxysql=>mysql3(replica)
    fn_sysbench_run
    fn_sysbench_check debezium
    if [ $? -ne 0 ]; then
      res=1
      results+=("$repl_chain FAILED")
    else
      results+=("$repl_chain passed")
    fi
  fi

  echo ""
  echo "================================================================================"
  echo "[`date '+%Y-%m-%d %H:%M:%S'`]"
  echo ${MYSQL_VERSION} ${SSL_} ${DEBEZIUM} "TEST SUMMARY"
  if [ $res -eq 0 ]; then
    echo "ALL TESTS WERE PASSED:"
  else
    echo "SOME TESTS WERE FAILED:"
  fi
  # print the results
  for result in "${results[@]}"; do
    echo "$result"
  done
  echo "================================================================================"

}

res=0

fn_run_main_test "$MYSQL_VERSION" "$SSL" "$DEBEZIUM" "$4"

#fn_stop

exit $res
