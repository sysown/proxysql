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

	# The Scheduler Hack: If we can't use docker (e.g. we're running
	# inside the test-runner container, which has no docker CLI), we ask
	# ProxySQL to kill itself. We install a scheduler row with interval
	# 500ms so it fires very quickly. We use /bin/sh -c to find the
	# correct PID (worker process) and signal it.
	#
	# NOTE: the caller is responsible for tearing the scheduler row down
	# via fn_signal_cleanup() after it has observed the effect it was
	# waiting for. We intentionally do NOT delete the row here - that
	# would race against the scheduler actually firing.
	echo "msg: # Using Scheduler Hack to send ${sig} to ProxySQL..."
	fn_padmin "INSERT OR REPLACE INTO scheduler (id, active, interval_ms, filename, arg1, arg2) VALUES (9999, 1, 500, '/bin/sh', '-c', 'kill -${sig#SIG} \$(pidof proxysql)');"
	fn_padmin "LOAD SCHEDULER TO RUNTIME;"
}

fn_signal_cleanup () {
	# Tear down any scheduler row installed by fn_signal. Safe to call
	# unconditionally - if fn_signal used the docker path instead of the
	# scheduler hack, this is a no-op on a non-existent row.
	fn_padmin "DELETE FROM scheduler WHERE id=9999;" >/dev/null 2>&1 || true
	fn_padmin "LOAD SCHEDULER TO RUNTIME;" >/dev/null 2>&1 || true
}

fn_get_rotations () {
	# Raw count of rotation markers in the current proxysql.log. No
	# sleep() here - callers that are racing against an in-progress
	# rotation should use fn_wait_for_rotation_at_least instead, which
	# polls in a bounded loop rather than relying on a fixed sleep.
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

fn_wait_for_rotation_at_least () {
	# Poll fn_get_rotations every 500 ms until the observed count is
	# >= $1, or until $2 seconds have elapsed. Prints the final observed
	# count to stdout so the caller can compare against its expected
	# value (even on timeout).
	#
	# This replaces the `fn_padmin COMMAND ; sleep N ; count` pattern
	# that used to race on slow CI runners: the sleep window was fixed
	# at 1-5 s but the actual rotation latency varies with runner load,
	# and any sleep just shy of the latency silently produced a false
	# failure. By polling we convert a timing race into a max-latency
	# bound - on a fast machine the test is as quick as before, on a
	# slow one it waits up to max_seconds instead of failing.
	local target=${1}
	local max_seconds=${2:-30}
	local i=0
	local count=0
	local max_iterations=$(( max_seconds * 2 ))
	while [ $i -lt $max_iterations ]; do
		count=$(fn_get_rotations)
		if [ "$count" -ge "$target" ]; then
			echo $count
			return 0
		fi
		sleep 0.5
		i=$(( i + 1 ))
	done
	# Timeout. Emit whatever we last observed so fn_check_res will
	# report a useful "BASELINE X expected Y got Z" message rather than
	# an empty RES.
	echo $count
	return 1
}

fn_check_res () {
	DONE=$(( $DONE + 1 ))
	PLAN=$([[ $PLAN -lt $DONE ]] && echo $DONE || echo $PLAN)
	# Accept any count >= BASELINE+1. The test asks "did this command
	# trigger at least one rotation" - two rotations (e.g. if the
	# scheduler hack fired twice before fn_signal_cleanup tore it down)
	# is still a pass signal. It used to be `-ne` which was stricter
	# than the actual test semantics and contributed to flakiness.
	if [[ $RES -lt $(( $BASELINE + 1)) ]]; then
		echo "msg: not ok $DONE - command '$1' - BASELINE: $BASELINE - expected at least $(( $BASELINE + 1)) : got $RES"
		FAIL=$(( $FAIL + 1 ))
	else
		echo "msg: ok $DONE - command '$1' - BASELINE: $BASELINE - got $RES (>= BASELINE + 1)"
	fi
}

# test init
fn_getenv
fn_plan


# test PROXYSQL FLUSH LOGS
BASELINE=$(fn_get_rotations)
fn_padmin "PROXYSQL FLUSH LOGS;"
RES=$(fn_wait_for_rotation_at_least $(( $BASELINE + 1 )) 30)
fn_check_res "PROXYSQL FLUSH LOGS;"

# test SIGUSR1 signal
BASELINE=$(fn_get_rotations)
fn_signal "SIGUSR1"
RES=$(fn_wait_for_rotation_at_least $(( $BASELINE + 1 )) 30)
fn_signal_cleanup
fn_check_res "kill -s SIGUSR1 \$PID"


# test done
