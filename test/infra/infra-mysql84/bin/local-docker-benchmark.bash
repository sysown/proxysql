#!/bin/bash
set -e

PREP_THREADS=1
RUN_THREADS=4
NUM_TABLES=5
SIZE_TABLES=10
REPORT_INTERVAL=1
TIME=10
SCRIPT=oltp_read_write.lua
MYSQL_PWD=root

printf "[$(date)] Dropping 'sysbench' schema if present and preparing test dataset:\n"
mysql -h127.0.0.1 -P6033 -uroot -p$MYSQL_PWD -e"DROP DATABASE IF EXISTS sysbench; CREATE DATABASE IF NOT EXISTS sysbench"

printf "[$(date)] Running Sysbench Benchmarks against ProxySQL:"
sysbench /usr/share/sysbench/$SCRIPT --table-size=$SIZE_TABLES --tables=$NUM_TABLES --threads=$PREP_THREADS \
 --mysql-db=sysbench --mysql-user=root --mysql-password=$MYSQL_PWD --mysql-host=127.0.0.1 --mysql-port=6033 --db-driver=mysql prepare

sleep 10

sysbench /usr/share/sysbench/$SCRIPT --table-size=$SIZE_TABLES --tables=$NUM_TABLES --threads=$RUN_THREADS \
 --mysql-db=sysbench --mysql-user=root --mysql-password=$MYSQL_PWD --mysql-host=127.0.0.1 --mysql-port=6033 \
 --time=$TIME --report-interval=$REPORT_INTERVAL --db-driver=mysql run

printf "[$(date)] Benchmarking COMPLETED!\n"
