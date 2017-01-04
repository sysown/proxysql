#!/bin/bash
PROXYSQL_USERNAME="admin"
PROXYSQL_PASSWORD="admin"
PROXYSQL_HOSTNAME="$1"
PROXYSQL_PORT_13311="$2"


PROXYSQL_CMDLINE_13311="mysql -u$PROXYSQL_USERNAME -p$PROXYSQL_PASSWORD -h $PROXYSQL_HOSTNAME -P $PROXYSQL_PORT_13311 --protocol=tcp -Nse"

$PROXYSQL_CMDLINE_13311 "SELECT count(*) from stats_mysql_query_digest"
$PROXYSQL_CMDLINE_13311 "SELECT count(*) from stats_mysql_commands_counters"
$PROXYSQL_CMDLINE_13311 "SELECT count(*) from stats_mysql_connection_pool"
$PROXYSQL_CMDLINE_13311 "SELECT count(*) from stats_mysql_global"
$PROXYSQL_CMDLINE_13311 "SELECT count(*) from stats_mysql_processlist"
$PROXYSQL_CMDLINE_13311 "SELECT count(*) from stats_mysql_query_rules"
