#!/bin/bash

. ../env.sh

# make sure we are in correct folder
trap popd EXIT
pushd $WORKSPACE/src


fn_proxysql_killall () {
	killall proxysql 2>/dev/null|| true
	killall mysql 2>/dev/null || true
	sleep 5
	killall -9 proxysql 2>/dev/null || true
	killall -9 mysql 2>/dev/null || true
}

SECONDS=0
echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Stopping ProxySQL ..."

(mysql -h127.0.0.1 -P6032 -uadmin -padmin -e"PROXYSQL SHUTDOWN SLOW" 2>&1 || true ) &

local counter=0
while [[ -n $(ss -ntpl | grep :6032) ]]; do
	sleep 1
	if [[ $counter -gt 60 ]]; then
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Killing ProxySQL ..."
		fn_proxysql_killall
	fi
	let counter++
done

echo "[$(date '+%Y-%m-%d %H:%M:%S')] >>> Stopping ProxySQL DONE in ${SECONDS}s"
