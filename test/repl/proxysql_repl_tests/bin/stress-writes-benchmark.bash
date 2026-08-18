#!/bin/bash
#set -e

. constants

PREP_THREADS=1
RUN_THREADS=4
NUM_TABLES=5
SIZE_TABLES=1000
REPORT_INTERVAL=1
TIME=3
SCRIPT=oltp_write_only.lua
MYSQL_HOST=${PROXYSQL_HOST}
MYSQL_PORT=${PROXYSQL_PORT}
MYSQL_PWD=root


echo "[`date '+%Y-%m-%d %H:%M:%S'`] Dropping 'sysbench' schema if present and preparing test dataset"
mysql -h$MYSQL_HOST -P$MYSQL_PORT -uroot -p$MYSQL_PWD -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE IF NOT EXISTS sysbench;" 2>&1 | grep -vP "mysql: .?Warning"

sysbench_prepare="sysbench /usr/share/sysbench/$SCRIPT --table-size=$SIZE_TABLES --tables=$NUM_TABLES --threads=$PREP_THREADS \
 --mysql-db=sysbench --mysql-user=sbtest1 --mysql-password=sbtest1 --mysql-host=$MYSQL_HOST --mysql-port=$MYSQL_PORT --db-driver=mysql prepare"

sysbench_run="sysbench /usr/share/sysbench/$SCRIPT --table-size=$SIZE_TABLES --tables=$NUM_TABLES --threads=$RUN_THREADS \
 --mysql-db=sysbench --mysql-user=root --mysql-password=$MYSQL_PWD --mysql-host=$MYSQL_HOST --mysql-port=$MYSQL_PORT \
 --time=$TIME --report-interval=$REPORT_INTERVAL --db-driver=mysql run"

if [[ ! -z "$1" ]]; then
  log_file="sysbench_prepare_$(date +%Y-%m-%d_%H-%M-%S).log"
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running sysbench prepare against proxysql"
  echo "Logging output to: "$1/$log_file
  $sysbench_prepare > "$1/$log_file" 2>&1
  sleep 3
  log_file="sysbench_run_$(date +%Y-%m-%d_%H-%M-%S).log"
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running sysbench writes-only against proxysql"
  echo "Logging output to: "$1/$log_file
  for i in $(seq 1 10)
  do
    echo "[`date '+%Y-%m-%d %H:%M:%S'`] Run $i ..."
    $sysbench_run >> "$1/$log_file" 2>&1
    sleep 3
  done
else
  echo "[`date '+%Y-%m-%d %H:%M:%S'`] Running sysbench against proxysql"
  $sysbench_prepare
  sleep 3
  $sysbench_run
 fi

sleep 3

echo "[`date '+%Y-%m-%d %H:%M:%S'`] Sysbench benchmarking completed"
