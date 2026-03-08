#!/bin/bash
set -o pipefail

set -e

PROXY_CONF_DIR=$(dirname "$(realpath "$0")")/../conf/proxysql

WAITED=0
TIMEOUT=300
RC=1

set +e

printf "[$(date)] Waiting for ProxySQL service to initialize"
while [ $RC -eq 1 ]; do
	if [ $WAITED -gt $TIMEOUT ]; then
		echo "[ERROR] Timeout of $TIMEOUT seconds reached while connecting to ProxySQL"
		exit 1
	else
		printf "."
		mysql -h$ADMIN_HOST -P$ADMIN_PORT -u$ADMIN_USER -p$ADMIN_PWD -e"\s" > /dev/null 2>&1
		RC=$?
		WAITED=$((WAITED+1))
		sleep 1
	fi
done
printf "\n"

set -e

echo "[$(date)] Applying initial config for ProxySQL ..."
set -x
mysql --prompt="admin> " -u$ADMIN_USER -p$ADMIN_PWD --table -h$ADMIN_HOST -P$ADMIN_PORT < "$PROXY_CONF_DIR"/config.sql
set +x
