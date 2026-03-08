#!/bin/bash
set -o pipefail

set -e

POSTGRE_SETUP_DIR=$(dirname "$(realpath "$0")")/../scripts/

WAITED=0
TIMEOUT=300
RC=1

set +e

printf "[$(date)] Waiting for PostgreSQL service to initialize"
while [ $RC -ne 0 ]; do
	if [ $WAITED -gt $TIMEOUT ]; then
		echo "[ERROR] Timeout of $TIMEOUT seconds reached while connecting to PostgreSQL"
		exit 1
	else
		printf "."
		PGPASSWORD=$PGSQL_PWD ON_ERROR_STOP=1 psql -h$PGSQL_HOST -p$PGSQL_PORT -U$PGSQL_DB -c"SELECT" > /dev/null 2>&1
		RC=$?
		WAITED=$((WAITED+1))
		sleep 1
	fi
done
printf "\n"

set -e

echo "[$(date)] Creating table structures for testing ..."
set -x
PGPASSWORD=$PGSQL_PWD ON_ERROR_STOP=1 psql -h$PGSQL_HOST -p$PGSQL_PORT -U$PGSQL_DB < "$POSTGRE_SETUP_DIR"/create_test_tables.sql
set +x
