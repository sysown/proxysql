#!/usr/bin/env bash
#
# configure 'tests_multiplexing_false'
#
# this script runs before running tests in this folder
#

# reconfigure proxysql
mysql -h ${TAP_ADMINHOST} -P ${TAP_ADMINPORT} -uadmin -padmin -e " \
SET mysql-multiplexing='false';
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
"

