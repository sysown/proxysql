#!/usr/bin/env bash
#
# test proxysql log flushing mechanisms
# - PROXYSQL FLUSH LOGS command
# - SIGUSR1 signal
#

# change plan here, 0 means auto plan
PLAN=0
DONE=0
FAIL=0

trap fn_exit EXIT
trap fn_exit SIGINT

PROXYSQL_PATH=$(while [ ! -f ./src/proxysql_global.cpp ]; do cd ..; done; pwd)
PROXYSQL_LOGS=${REGULAR_INFRA_DATADIR:-$PROXYSQL_PATH/src}

fn_getenv () {
	source .env 2>/dev/null
	source $(basename $(dirname $0)).env 2>/dev/null
	source $(basename $0 | sed 's/.sh//').env 2>/dev/null
}

fn_plan () {
	PLAN=${1:-$PLAN}
	echo "msg: 1..${PLAN/#0/}"
}

fn_exit () {
	trap - EXIT
	trap - SIGINT
	if [[ $DONE -eq $PLAN ]] && [[ $FAIL -eq 0 ]]; then
		echo "msg: Test took $SECONDS sec"
		exit 0
	else
		echo "msg: plan was $PLAN - done $DONE"
		echo "msg: from $DONE done - $FAIL failed"
		echo "msg: Test took $SECONDS sec"
		exit 1
	fi
}

fn_padmin () {
	mysql -u${TAP_ADMINUSERNAME:-admin} -p${TAP_ADMINPASSWORD:-admin} -h${TAP_ADMINHOST:-127.0.0.1} -P${TAP_ADMINPORT:-6032} -e "${1}" 2>&1 | grep -vP "mysql: .?Warning"
}

fn_signal () {
	# send signal to all - watchdog and worker processes
#	ps aux | grep -P 'proxysql ' | grep -v 'grep' | awk '{ print $2 }' | sudo xargs -n1 kill -s ${1}
	# send signal only to worker processes
#	ps aux | grep -P 'proxysql ' | grep -v 'grep' | awk '{ print $2 }' | sort -n | sed '1 !d' | sudo xargs -n1 kill -s ${1}
	sudo netstat -ntpl | grep proxysql | tr '/' ' ' | awk '{ print $7 }' | sort | uniq | sudo xargs -r -n1 kill -s ${1}
}

fn_get_rotations () {
	sleep 1
	cat $PROXYSQL_LOGS/proxysql.log | grep '\[INFO\] ProxySQL version' | wc -l
}

fn_check_res () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)
	if [[ $RES -ne $(( $BASELINE + 1)) ]]; then
		echo "msg: not ok $DONE - command '$1' - initial BASELINE: $BASELINE - expected BASELINE + 1 : got $RES"
		FAIL=$(( $FAIL + 1 ))
	else
		echo "msg: ok $DONE - command '$1' - initial BASELINE: $BASELINE - expected BASELINE + 1 : got $RES"
	fi
}

# test init
fn_getenv
fn_plan


# test PROXYSQL FLUSH LOGS
BASELINE=$(fn_get_rotations)
fn_padmin "PROXYSQL FLUSH LOGS;"
RES=$(fn_get_rotations)
fn_check_res "PROXYSQL FLUSH LOGS;"

# test SIGUSR1 signal
BASELINE=$(fn_get_rotations)
fn_signal "SIGUSR1"
RES=$(fn_get_rotations)
fn_check_res "kill -s SIGUSR1 \$PID"


# test done
