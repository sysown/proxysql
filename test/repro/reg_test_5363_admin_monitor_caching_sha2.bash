#!/usr/bin/env bash
#
# reg_test_5363_admin_monitor_caching_sha2.bash
#
# Reproduces: the mysql-monitor_username / mysql-monitor_password credential
# cannot authenticate on the ProxySQL Admin interface (:6032) when
# mysql-default_authentication_plugin = 'caching_sha2_password'.
# It works under mysql_native_password. TLS does not help.
#
#   https://github.com/sysown/proxysql/issues/5363   (k8s liveness/readiness
#                                                     probes failing)
#   https://github.com/sysown/proxysql/issues/5985   Finding 2
#
# EXPECTED EXIT CODE
#   Non-zero WHILE THE BUG EXISTS. The assertions below describe the desired
#   behaviour, so the caching_sha2 cases fail today and are tagged [BUG #5363].
#   When the bug is fixed this script must exit 0 with no tagged failures.
#
# ROOT CAUSE (for the reader; not asserted by this script)
#   mysql-monitor_* is not stored in GloMyAuth, so PPHR_verify_password() takes
#   its vars1.password == NULL branch and the credential is handled solely by
#   MySQL_Protocol::PPHR_5passwordFalse_0() (lib/MySQL_Protocol.cpp:2052), which
#   is hardcoded to the mysql_native_password scramble:
#       proxy_scramble(reply, scramble_buff, mysql_thread___monitor_password);
#       if (memcmp(reply, vars1.pass, SHA_DIGEST_LENGTH)==0)   // 20 bytes
#   Under caching_sha2_password the client's fast-auth response is a 32-byte
#   SHA256-derived value, so this comparison can never succeed. The pre-existing
#   comment on line 2053 -- "FIXME: does this work only for mysql_native_password ?"
#   -- is this bug.
#
# WHY THE CLIENT RUNS INSIDE THE CONTAINER
#   The monitor credential is subject to a locality restriction: connecting from
#   off-box yields "ERROR 1040 User 'monitor' can only connect locally", which is
#   raised AFTER a successful authentication and would mask the result. Running
#   the client on 127.0.0.1 inside the container both avoids that and matches the
#   real-world case in #5363 (a probe running inside the pod).
#
# SCOPE
#   No mysql_users rows are created and no admin credential named 'monitor'
#   exists, so PPHR_5passwordFalse_0() is genuinely the code path under test.
#   A control case proves caching_sha2 itself works on Admin, so a failure here
#   is specific to the monitor credential.
#
# REQUIREMENTS
#   DEBUG build at $WORKSPACE/src/proxysql:
#       make clean && PROXYSQL31=1 make debug -j"$(nproc)"
#
# USAGE
#   WORKSPACE=$(pwd) INFRA_ID=dev-$USER \
#     test/repro/reg_test_5363_admin_monitor_caching_sha2.bash
#
# COLD START
#   Not required by this script -- the monitor credential never touches the
#   caching_sha2 cleartext cache -- but available for a guaranteed-clean run:
#
#     COLD_START=1   destroy and recreate the ProxySQL instance first. DESTRUCTIVE:
#                    deletes the persisted proxysql.db for $INFRA_ID. Backend
#                    infrastructure and other INFRA_IDs are untouched.
#     COLD_START=0   (default) use the instance as-is.
#
#   Either way the script refuses to run if the container predates
#   $WORKSPACE/src/proxysql, since that would test a binary you did not just build.
#
set -uo pipefail

WORKSPACE="${WORKSPACE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
INFRA_ID="${INFRA_ID:-dev-$USER}"
TAP_GROUP="${TAP_GROUP:-no-infra-g1}"
COLD_START="-e"
export WORKSPACE INFRA_ID TAP_GROUP

CTR="proxysql.${INFRA_ID}"
DATADIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/proxysql"
MON_USER='monitor'
MON_PASS='monitorpass'
LOAD_MYSQL_VARS='LOAD MYSQL VARIABLES TO RUNTIME;'

PASS=0; FAIL=0; BUGS=0
ok()  { local msg="$1"; PASS=$((PASS+1)); printf '  ok %d - %s\n'     "$((PASS+FAIL))" "$msg"; return 0; }
nok() { local msg="$1"; FAIL=$((FAIL+1)); printf '  NOT OK %d - %s\n' "$((PASS+FAIL))" "$msg"; return 0; }
bug() { local msg="$1"; FAIL=$((FAIL+1)); BUGS=$((BUGS+1)); printf '  NOT OK %d - [BUG #5363] %s\n' "$((PASS+FAIL))" "$msg"; return 0; }
hdr() { local msg="$1"; printf '\n== %s ==\n' "$msg"; return 0; }
die() { local msg="$1"; printf '\nFATAL: %s\n' "$msg" >&2; exit 2; }

IP=''
adm() {
	local sql="$1"
	mysql -h"$IP" -P6032 -uradmin -pradmin --protocol=TCP -NBe "$sql" 2>/dev/null
	return $?
}
setvar() {  # setvar <variable_name> <value> <LOAD statement>
	local name="$1" value="$2" load_stmt="$3"
	adm "UPDATE global_variables SET variable_value='$value' WHERE variable_name='$name'; $load_stmt" >/dev/null
	return $?
}
# login_local <user> <pass> <ssl-mode>  -- runs the client INSIDE the container
login_local() {
	local user="$1" pass="$2" ssl_mode="$3"
	docker exec "$CTR" mysql -h127.0.0.1 -P6032 -u"$user" -p"$pass" \
		--protocol=TCP --ssl-mode="$ssl_mode" -NBe "SELECT 1;" >/dev/null 2>&1
	return $?
}

# ------------------------------------------------------------- preflight ---
command -v docker >/dev/null || die "docker not found"
command -v mysql  >/dev/null || die "mysql client not found"
[[ -x "${WORKSPACE}/src/proxysql" ]] || die "no binary at ${WORKSPACE}/src/proxysql -- build it first"
"${WORKSPACE}/src/proxysql" --version 2>&1 | grep -q '_DEBUG' \
	|| die "${WORKSPACE}/src/proxysql is not a DEBUG build"

# ------------------------------------------------------------ instance ---
# This script does NOT need a cold cache: the monitor credential is handled by
# PPHR_5passwordFalse_0(), which never calls set_clear_text_password(), so the
# caching_sha2 cleartext cache plays no part in the result. COLD_START is offered
# only for symmetry with the #5985 companion and for a guaranteed-clean run.
if [[ "$COLD_START" = "1" ]]; then
	hdr "Cold start: destroying and recreating ProxySQL for INFRA_ID=${INFRA_ID}"
	"${WORKSPACE}/test/infra/control/stop-proxysql-isolated.bash" >/dev/null 2>&1
	rm -f "${DATADIR}"/proxysql.db "${DATADIR}"/proxysql_debug.db \
	      "${DATADIR}"/proxysql_stats.db "${DATADIR}"/sqlite3server.db 2>/dev/null
	"${WORKSPACE}/test/infra/control/start-proxysql-isolated.bash" >/dev/null 2>&1 \
		|| die "start-proxysql-isolated.bash failed"
else
	hdr "Using the existing ProxySQL instance (set COLD_START=1 to recreate it)"
	"${WORKSPACE}/test/infra/control/ensure-infras.bash" >/dev/null 2>&1 \
		|| die "ensure-infras.bash failed"
fi

IP="$(docker inspect "$CTR" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)"
[[ -n "$IP" ]] || die "could not determine IP of ${CTR}"
docker exec "$CTR" which mysql >/dev/null 2>&1 || die "no mysql client inside ${CTR}"

# Guard against testing a STALE binary. The container bind-mounts
# $WORKSPACE/src/proxysql, but the RUNNING process is whatever was started: a
# rebuild does not restart it, and ensure-infras.bash deliberately will not
# recreate a container that is already up. Without this check a freshly built fix
# can appear absent -- or a reverted one appear present -- purely because the
# container predates the binary, which is a very easy way to draw the wrong
# conclusion from this script.
BIN_MTIME="$(stat -c %Y "${WORKSPACE}/src/proxysql" 2>/dev/null || echo 0)"
CTR_STARTED="$(docker inspect -f '{{.State.StartedAt}}' "$CTR" 2>/dev/null)"
CTR_EPOCH="$(date -d "$CTR_STARTED" +%s 2>/dev/null || echo 0)"
if [[ "$BIN_MTIME" -gt "$CTR_EPOCH" ]] 2>/dev/null; then
	die "the running ProxySQL container predates ${WORKSPACE}/src/proxysql, so it is
       NOT running the binary you just built. Re-run with COLD_START=1, or refresh
       the container with:
         WORKSPACE=\$(pwd) INFRA_ID=${INFRA_ID} TAP_GROUP=${TAP_GROUP} \\
           test/infra/control/start-proxysql-isolated.bash"
fi
echo "  ${CTR} at ${IP} -- $(adm 'SELECT @@admin-version;')"

# Capture the instance's ACTUAL pre-existing values so the EXIT handler can put
# back exactly what was there. Restoring hardcoded defaults instead would
# silently rewrite the configuration of a shared instance -- see the "Restore any
# global state that was changed" rule in test/repro/README.md. Note this script
# never modifies 'admin-admin_credentials', so it must not reset it either.
ORIG_AUTH_PLUGIN="$(adm 'SELECT @@mysql-default_authentication_plugin;')"
ORIG_MON_USER="$(adm 'SELECT @@mysql-monitor_username;')"
ORIG_MON_PASS="$(adm 'SELECT @@mysql-monitor_password;')"

restore() {
	setvar 'mysql-default_authentication_plugin' "$ORIG_AUTH_PLUGIN" "$LOAD_MYSQL_VARS"
	setvar 'mysql-monitor_username' "$ORIG_MON_USER" "$LOAD_MYSQL_VARS"
	setvar 'mysql-monitor_password' "$ORIG_MON_PASS" "$LOAD_MYSQL_VARS"
	return 0
}
trap restore EXIT

# ----------------------------------------------------------- preconditions ---
hdr "Preconditions"
[[ "$(adm 'SELECT count(*) FROM runtime_mysql_users;')" = "0" ]] \
	&& ok "no mysql_users rows (nothing can shadow the monitor credential)" \
	|| nok "mysql_users is not empty -- result would be confounded"
adm "SELECT @@admin-admin_credentials;" | grep -q "${MON_USER}:" \
	&& nok "an admin credential named '${MON_USER}' exists -- wrong code path" \
	|| ok "no admin credential named '${MON_USER}' (PPHR_5passwordFalse_0 is the path)"

setvar 'mysql-monitor_username' "$MON_USER" "$LOAD_MYSQL_VARS"
setvar 'mysql-monitor_password' "$MON_PASS" "$LOAD_MYSQL_VARS"
[[ "$(adm 'SELECT @@mysql-monitor_username;')" = "$MON_USER" ]] &&
[[ "$(adm 'SELECT @@mysql-monitor_password;')" = "$MON_PASS" ]] \
	&& ok "mysql-monitor_username/password set to ${MON_USER}/${MON_PASS} (cleartext, as documented)" \
	|| nok "failed to set mysql-monitor_* variables"

# ------------------------------------------------- baseline: native works ---
hdr "Baseline: mysql_native_password"
setvar 'mysql-default_authentication_plugin' 'mysql_native_password' "$LOAD_MYSQL_VARS"
login_local "$MON_USER" "$MON_PASS" DISABLED \
	&& ok  "${MON_USER} authenticates on :6032 over plaintext" \
	|| nok "${MON_USER} FAILED under native/plaintext -- baseline broken, investigate before trusting the rest"
login_local "$MON_USER" "$MON_PASS" REQUIRED \
	&& ok  "${MON_USER} authenticates on :6032 over TLS" \
	|| nok "${MON_USER} FAILED under native/TLS -- baseline broken"

# ------------------------------------------------------------- the bug ---
hdr "caching_sha2_password"
setvar 'mysql-default_authentication_plugin' 'caching_sha2_password' "$LOAD_MYSQL_VARS"
[[ "$(adm 'SELECT @@mysql-default_authentication_plugin;')" = "caching_sha2_password" ]] \
	&& ok "mysql-default_authentication_plugin = caching_sha2_password" \
	|| nok "failed to switch the default authentication plugin"

login_local "$MON_USER" "$MON_PASS" DISABLED \
	&& ok  "${MON_USER} authenticates on :6032 over plaintext" \
	|| bug "${MON_USER} cannot authenticate on :6032 over plaintext (Access denied)"
login_local "$MON_USER" "$MON_PASS" REQUIRED \
	&& ok  "${MON_USER} authenticates on :6032 over TLS" \
	|| bug "${MON_USER} cannot authenticate on :6032 over TLS -- TLS is not a workaround"

# -------------------------------------------------------------- control ---
# Proves the failure above is specific to the monitor credential and not to
# caching_sha2 on the Admin interface generally.
hdr "Control: an ordinary admin credential under the same settings"
login_local admin admin DISABLED \
	&& ok  "admin/admin authenticates on :6032 under caching_sha2 (so caching_sha2 works on Admin)" \
	|| nok "admin/admin also failed -- the monitor result is not specific; investigate"
login_local "$MON_USER" "WRONGPASS" DISABLED \
	&& nok "a wrong monitor password was ACCEPTED" \
	|| ok  "wrong monitor password rejected"

# --------------------------------------------------------------- summary ---
hdr "Summary"
printf '  passed: %d\n  failed: %d (of which %d are the reported bug)\n' "$PASS" "$FAIL" "$BUGS"
if [[ "$FAIL" -eq 0 ]]; then
	echo
	echo "  All assertions pass: #5363 appears FIXED on this build."
	exit 0
fi
if [[ "$FAIL" -eq "$BUGS" ]]; then
	cat <<'EOS'

  REPRODUCED. Every failure is a [BUG #5363] assertion:
    mysql-monitor_* authenticates on the Admin interface under
    mysql_native_password and is rejected under caching_sha2_password, on both
    plaintext and TLS, with no mysql_users row and no same-named admin
    credential involved. An ordinary admin credential works under the identical
    settings, so this is specific to the monitor credential.

  Non-zero exit is expected until the bug is fixed.
EOS
	exit 1
fi
echo
echo "  Some failures are NOT the reported bug -- the environment or baseline is wrong."
exit 2
