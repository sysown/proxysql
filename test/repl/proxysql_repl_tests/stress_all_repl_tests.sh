#!/usr/bin/bash

res=0

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

if [ -z "${WORKSPACE}" ]; then
    echo "WORKSPACE is empty, please check ../env.sh"
    exit 1
elif [ -z "${REPL_TESTS_PATH}" ]; then
    echo "REPL_TESTS_PATH is empty, please check ../env.sh"
    exit 1
elif [ -z "${REPL_INFRA_DATADIR}" ]; then
    echo "REPL_INFRA_DATADIR is empty, please check ../env.sh"
    exit 1
fi


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

# array for the script execution results
results=()

# always run with debezium
debezium="debezium"

# run stress_repl_test.sh for each mysql version with/without ssl, pass $2 which might be 'no_binlog_checksum'
for mysql_ver in "5.6" "5.7" "8.0"
do
  for ssl_par in "no-ssl" "ssl"
  do

    if [ "$mysql_ver" == "5.6" ] && [ "$ssl_par" == "ssl" ]; then
      : # skip 5.6 ssl
    elif [ "$mysql_ver" == "5.6" ] || [ "$mysql_ver" == "8.0" ] ; then
      # run  5.6/8.0 without debezium for now
      ./stress_repl_test.sh "$mysql_ver" "$ssl_par" "" "$2"

      if [ $? -ne 0 ]; then
        res=1
        results+=("test run mysql$mysql_ver $ssl_par $2 FAILED")
      else
        results+=("test run mysql$mysql_ver $ssl_par $2 PASSED")
      fi

    else
      # run full test

      ./stress_repl_test.sh "$mysql_ver" "$ssl_par" "$debezium" "$2"

      if [ $? -ne 0 ]; then
        res=1
        results+=("test run mysql$mysql_ver $ssl_par $debezium $2 FAILED")
      else
        results+=("test run mysql$mysql_ver $ssl_par $debezium $2 PASSED")
      fi

    fi

  done
done

if [ "$1" != "no_shutdown" ]; then
  fn_stop
fi

echo ""
echo "================================================================================"
if [ $res -eq 0 ]; then
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] TOTAL SUMMARY: ALL TESTS WERE PASSED"
else
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] TOTAL SUMMARY: SOME TESTS WERE FAILED"
fi
echo ""
# print the results
for result in "${results[@]}"; do
  echo "$result"
done
echo "================================================================================"

exit $res
