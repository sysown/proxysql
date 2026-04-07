#!/bin/bash
#set -e
set -o pipefail

PREP_THREADS=1
RUN_THREADS=4
NUM_TABLES=5
SIZE_TABLES=10
REPORT_INTERVAL=1
TIME=10
SCRIPT=oltp_read_write.lua
MYSQL_HOST=${TAP_ROOTHOST:-127.0.0.1}
MYSQL_PORT=${TAP_ROOTPORT:-6033}
MYSQL_PWD=${TAP_ROOTPASSWORD:-root}

printf "[$(date)] Dropping 'sysbench' schema if present and preparing test dataset:\n"
mysql -h$MYSQL_HOST -P$MYSQL_PORT -uroot -p$MYSQL_PWD -e"DROP DATABASE IF EXISTS sysbench; CREATE DATABASE IF NOT EXISTS sysbench;" 2>&1 | grep -vP 'mysql: .?Warning'

printf "[$(date)] Running Sysbench Benchmarks against ProxySQL:"
sysbench /usr/share/sysbench/$SCRIPT --table-size=$SIZE_TABLES --tables=$NUM_TABLES --threads=$PREP_THREADS \
 --mysql-db=sysbench --mysql-user=root --mysql-password=$MYSQL_PWD --mysql-host=$MYSQL_HOST --mysql-port=$MYSQL_PORT --db-driver=mysql prepare

sleep 10

sysbench /usr/share/sysbench/$SCRIPT --table-size=$SIZE_TABLES --tables=$NUM_TABLES --threads=$RUN_THREADS \
 --mysql-db=sysbench --mysql-user=root --mysql-password=$MYSQL_PWD --mysql-host=$MYSQL_HOST --mysql-port=$MYSQL_PORT \
 --time=$TIME --report-interval=$REPORT_INTERVAL --db-driver=mysql run

printf "[$(date)] Benchmarking COMPLETED!\n"
