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

# Debugging: show environment if needed
if [[ -n "${TAP_DEBUG}" ]]; then
	set -x
fi

# Locate the ProxySQL path safely
PROXYSQL_PATH=$(
	curr_dir=$(pwd)
	while [[ "$curr_dir" != "/" ]] && [[ ! -f "$curr_dir/src/proxysql_global.cpp" ]]; do
		curr_dir=$(dirname "$curr_dir")
	done
	if [[ -f "$curr_dir/src/proxysql_global.cpp" ]]; then
		echo "$curr_dir"
	else
		echo "."
	fi
)
PROXYSQL_LOGS=${REGULAR_INFRA_DATADIR:-$PROXYSQL_PATH/src}

echo "msg: # DEBUG: PROXY_CONTAINER='${PROXY_CONTAINER}'"
echo "msg: # DEBUG: TAP_ADMINHOST='${TAP_ADMINHOST}'"
echo "msg: # DEBUG: PROXYSQL_LOGS='${PROXYSQL_LOGS}'"

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
	local sig=${1}
	if command -v docker >/dev/null 2>&1; then
		if [ -n "$PROXY_CONTAINER" ]; then
			docker kill --signal ${sig} "$PROXY_CONTAINER"
			return
		fi
	fi

	# The Scheduler Hack: If we can't use docker, we ask ProxySQL to kill itself
	# ProxySQL scheduler waits for the first interval before execution.
	# We use /bin/sh -c to find the correct PID (worker process) and signal it.
	echo "msg: # Using Scheduler Hack to send ${sig} to ProxySQL..."
	fn_padmin "INSERT OR REPLACE INTO scheduler (id, active, interval_ms, filename, arg1, arg2) VALUES (9999, 1, 2000, '/bin/sh', '-c', 'kill -${sig#SIG} \$(pidof proxysql)');"
	fn_padmin "LOAD SCHEDULER TO RUNTIME;"
	sleep 4
	fn_padmin "DELETE FROM scheduler WHERE id=9999; LOAD SCHEDULER TO RUNTIME;"
}

fn_get_rotations () {
	sleep 1
	# Try local mount first (most efficient in CI)
	if [ -f "$PROXYSQL_LOGS/proxysql.log" ]; then
		cat "$PROXYSQL_LOGS/proxysql.log" | grep '\[INFO\] ProxySQL version' | wc -l
	elif [ -n "$TAP_GET_LOGS_COMMAND" ]; then
		$TAP_GET_LOGS_COMMAND | grep '\[INFO\] ProxySQL version' | wc -l
	elif command -v docker >/dev/null 2>&1 && [ -n "$PROXY_CONTAINER" ]; then
		docker exec "$PROXY_CONTAINER" cat /var/lib/proxysql/proxysql.log | grep '\[INFO\] ProxySQL version' | wc -l
	else
		# Fallback to local path relative to script
		cat $PROXYSQL_LOGS/proxysql.log 2>/dev/null | grep '\[INFO\] ProxySQL version' | wc -l || echo 0
	fi
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
