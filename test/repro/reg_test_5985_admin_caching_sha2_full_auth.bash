#!/usr/bin/env bash
#
# reg_test_5985_admin_caching_sha2_full_auth.bash
#
# Demonstrates that caching_sha2_password FULL AUTHENTICATION works on the
# ProxySQL ADMIN interface (:6032) against a caching_sha2-hashed credential.
#
# Context: https://github.com/sysown/proxysql/issues/5985
#   Ask 2 of that issue asserts that Admin fails to verify a cleartext password
#   received over TLS, and asks for the Admin full-auth completion to be fixed.
#   This script shows that completion already works.
#
# HOW THE RESULT IS PROVEN
#   caching_sha2_password completes either by FAST auth (challenge-response,
#   possible only when ProxySQL can derive the password) or by FULL auth
#   (ProxySQL sends 'perform full authentication' 0x04 and the client returns
#   the cleartext over TLS). With only a hash stored, fast auth is impossible.
#
#   ProxySQL caches the cleartext recovered by a successful full auth and reuses
#   it later; every cache HIT increments
#       stats_mysql_global.Client_Connections_sha2cached
#   A login that succeeds while that counter is still 0 therefore cannot have
#   come from the cache, and must have completed a full auth. That is the
#   assertion this script is built around, which is why it insists on a cold
#   start: a warm cache would invalidate the proof.
#
# SCOPE
#   Only the question above. No mysql_users rows are created (issue #5985
#   Finding 1 is a different problem and would confound the result), and
#   mysql-monitor_* is not touched (#5363 is a different bug on a different
#   code path).
#
# REQUIREMENTS
#   - DEBUG build at $WORKSPACE/src/proxysql:
#         make clean && PROXYSQL31=1 make debug -j"$(nproc)"
#   - docker, and a MySQL client supporting --ssl-mode
#
# USAGE
#   WORKSPACE=$(pwd) INFRA_ID=dev-$USER \
#     test/repro/reg_test_5985_admin_caching_sha2_full_auth.bash
#
# COLD START
#   This script REQUIRES a cold cleartext cache, because the whole proof is that a
#   login succeeded while Client_Connections_sha2cached was still 0.
#
#     COLD_START=1   destroy and recreate the ProxySQL instance first. DESTRUCTIVE:
#                    deletes the persisted proxysql.db for $INFRA_ID. Backend
#                    infrastructure and other INFRA_IDs are untouched.
#     COLD_START=0   (default) use the instance as-is. If the cache is already warm
#                    the script exits 2 rather than reporting a meaningless pass.
#
set -uo pipefail

WORKSPACE="${WORKSPACE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
INFRA_ID="${INFRA_ID:-dev-$USER}"
TAP_GROUP="${TAP_GROUP:-no-infra-g1}"
COLD_START="-e"
export WORKSPACE INFRA_ID TAP_GROUP

CTR="proxysql.${INFRA_ID}"
DATADIR="${WORKSPACE}/ci_infra_logs/${INFRA_ID}/proxysql"
USR='cs2adm'
PW='secret'
LOAD_MYSQL_VARS='LOAD MYSQL VARIABLES TO RUNTIME;'

PASS=0; FAIL=0
ok()  { local msg="$1"; PASS=$((PASS+1)); printf '  ok %d - %s\n'     "$((PASS+FAIL))" "$msg"; return 0; }
nok() { local msg="$1"; FAIL=$((FAIL+1)); printf '  NOT OK %d - %s\n' "$((PASS+FAIL))" "$msg"; return 0; }
hdr() { local msg="$1"; printf '\n== %s ==\n' "$msg"; return 0; }
die() { local msg="$1"; printf '\nFATAL: %s\n' "$msg" >&2; exit 2; }

IP=''
adm() {
	local sql="$1"
	mysql -h"$IP" -P6032 -uradmin -pradmin --protocol=TCP -NBe "$sql" 2>/dev/null
	return $?
}
sha2cached() {
	adm "SELECT Variable_Value FROM stats_mysql_global WHERE Variable_Name='Client_Connections_sha2cached';"
	return $?
}
login() {  # login <user> <pass> <ssl-mode> -> 0 on success
	local user="$1" pass="$2" ssl_mode="$3"
	mysql -h"$IP" -P6032 -u"$user" -p"$pass" --protocol=TCP --ssl-mode="$ssl_mode" -NBe "SELECT 1;" >/dev/null 2>&1
	return $?
}

# ------------------------------------------------------------- preflight ---
command -v docker >/dev/null || die "docker not found"
command -v mysql  >/dev/null || die "mysql client not found"
[[ -x "${WORKSPACE}/src/proxysql" ]] || die "no binary at ${WORKSPACE}/src/proxysql -- build it first"
"${WORKSPACE}/src/proxysql" --version 2>&1 | grep -q '_DEBUG' \
	|| die "${WORKSPACE}/src/proxysql is not a DEBUG build"

# ------------------------------------------------------------ instance ---
# This script REQUIRES a cold cleartext cache: the whole proof is that a login
# succeeded while Client_Connections_sha2cached was still 0. If the cache is warm
# the run is aborted rather than reporting a meaningless pass -- see the guard
# immediately after the instance is up.
if [[ "$COLD_START" = "1" ]]; then
	hdr "Cold start: destroying and recreating ProxySQL for INFRA_ID=${INFRA_ID}"
	"${WORKSPACE}/test/infra/control/stop-proxysql-isolated.bash" >/dev/null 2>&1
	rm -f "${DATADIR}"/proxysql.db "${DATADIR}"/proxysql_debug.db \
	      "${DATADIR}"/proxysql_stats.db "${DATADIR}"/sqlite3server.db 2>/dev/null
	docker ps -a --filter "name=^${CTR}$" --format '{{.Names}}' | grep -q . \
		&& die "container ${CTR} still present after stop"
	"${WORKSPACE}/test/infra/control/start-proxysql-isolated.bash" >/dev/null 2>&1 \
		|| die "start-proxysql-isolated.bash failed"
else
	hdr "Using the existing ProxySQL instance (set COLD_START=1 to recreate it)"
	"${WORKSPACE}/test/infra/control/ensure-infras.bash" >/dev/null 2>&1 \
		|| die "ensure-infras.bash failed"
fi

IP="$(docker inspect "$CTR" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null)"
[[ -n "$IP" ]] || die "could not determine IP of ${CTR}"
echo "  ${CTR} at ${IP} -- $(adm 'SELECT @@admin-version;')"

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

# Hard requirement, not an assertion: without a cold cache the central claim
# cannot be tested at all, so refuse to run rather than emit a false pass.
if [[ "$(sha2cached)" != "0" ]]; then
	die "Client_Connections_sha2cached is '$(sha2cached)', not 0: the cleartext cache is
       already warm, so a successful login here would prove nothing. Re-run with
       COLD_START=1 to recreate the instance."
fi

# Capture the instance's ACTUAL pre-existing values so the EXIT handler can put
# back exactly what was there. This script appends a credential to
# 'admin-admin_credentials' and switches the default authentication plugin;
# restoring hardcoded defaults instead would discard whatever the shared instance
# was configured with -- see the "Restore any global state that was changed" rule
# in test/repro/README.md.
ORIG_ADMIN_CREDS="$(adm 'SELECT @@admin-admin_credentials;')"
ORIG_AUTH_PLUGIN="$(adm 'SELECT @@mysql-default_authentication_plugin;')"

restore() {
	adm "UPDATE global_variables SET variable_value='${ORIG_ADMIN_CREDS}' WHERE variable_name='admin-admin_credentials';
	     LOAD ADMIN VARIABLES TO RUNTIME;
	     UPDATE global_variables SET variable_value='${ORIG_AUTH_PLUGIN}' WHERE variable_name='mysql-default_authentication_plugin';
	     ${LOAD_MYSQL_VARS}" >/dev/null
	return 0
}
trap restore EXIT

hdr "Preconditions"
[[ "$(adm 'SELECT count(*) FROM runtime_mysql_users;')" = "0" ]] \
	&& ok "no mysql_users rows (Finding 1 cannot interfere)" \
	|| nok "mysql_users is not empty -- result would be confounded"
[[ "$(sha2cached)" = "0" ]] \
	&& ok "Client_Connections_sha2cached == 0 (cleartext cache is cold)" \
	|| nok "cleartext cache already warm -- the full-auth proof would be invalid"

# --------------------------------------------------- install credential ---
# The hash is generated by ProxySQL's own CACHING_SHA2_PASSWORD() and appended
# in SQL, so it never passes through the shell. Note this uses
# UPDATE global_variables rather than SET: a SET whose value carries a control
# byte -- which CACHING_SHA2_PASSWORD() salts contain most of the time -- is
# silently ignored, leaving the old value in place.
hdr "Installing a caching_sha2-hashed Admin credential"
adm "UPDATE global_variables SET variable_value='caching_sha2_password' WHERE variable_name='mysql-default_authentication_plugin';
     LOAD MYSQL VARIABLES TO RUNTIME;" >/dev/null
[[ "$(adm 'SELECT @@mysql-default_authentication_plugin;')" = "caching_sha2_password" ]] \
	&& ok "mysql-default_authentication_plugin = caching_sha2_password" \
	|| nok "failed to set the default authentication plugin"

# Work around issue #5989 so it cannot influence the result of THIS test.
#
# Before #5989 was fixed, CACHING_SHA2_PASSWORD() drew its 20-byte salt from an
# unrestricted byte range, so ~27% of generated hashes contained ';' or ':'.
# admin-admin_credentials is tokenized on ';' and split on ':' by
# ProxySQL_Admin::add_credentials(), so such a hash is silently split into a bogus
# credential at LOAD ADMIN VARIABLES TO RUNTIME -- the variable still holds all 70
# bytes and nothing errors, so a length check alone does NOT catch it, and the
# login simply fails with a generic 'Access denied'.
#
# Regenerating until the hash is delimiter-free keeps that separate bug from being
# misread as a full-auth failure here. On a build carrying the #5989 fix the loop
# succeeds on the first attempt; it is retained so this script still gives a
# correct answer when run against an older binary.
EXPECT_LEN=$(( ${#ORIG_ADMIN_CREDS} + 1 + ${#USR} + 1 + 70 ))
TAIL_EXPR="SUBSTR(variable_value, INSTR(variable_value,';${USR}:')+$(( ${#USR} + 2 )))"
CLEAN=0
for _ in $(seq 1 20); do
	adm "UPDATE global_variables SET variable_value='${ORIG_ADMIN_CREDS}' WHERE variable_name='admin-admin_credentials';
	     UPDATE global_variables
	        SET variable_value = variable_value || ';${USR}:' || CACHING_SHA2_PASSWORD('${PW}')
	      WHERE variable_name='admin-admin_credentials';" >/dev/null
	read -r LEN SEMI COLON <<<"$(adm "SELECT LENGTH(variable_value), INSTR(${TAIL_EXPR},';'), INSTR(${TAIL_EXPR},':') FROM global_variables WHERE variable_name='admin-admin_credentials';")"
	if [[ "$LEN" = "$EXPECT_LEN" && "$SEMI" = "0" && "$COLON" = "0" ]]; then CLEAN=1; break; fi
done
[[ "$CLEAN" = "1" ]] \
	&& ok "generated a 70-byte \$A\$ hash free of ';' and ':' (credentials len ${LEN})" \
	|| nok "could not generate a delimiter-free hash in 20 attempts"
adm "LOAD ADMIN VARIABLES TO RUNTIME;" >/dev/null
[[ "$(sha2cached)" = "0" ]] \
	&& ok "cache still cold immediately before the auth test" \
	|| nok "cache warmed prematurely"

# ============================== THE RESULT ==============================
hdr "RESULT: caching_sha2 full auth on the Admin interface"
login "$USR" "$PW" REQUIRED \
	&& ok  "${USR} authenticated on :6032 over TLS against a \$A\$ hash" \
	|| nok "${USR} FAILED on :6032 over TLS -- full auth did not complete"

C="$(sha2cached)"
[[ "$C" = "0" ]] \
	&& ok "Client_Connections_sha2cached still 0 -> that was a FULL AUTH, not a cache hit" \
	|| nok "counter is ${C} -- the login may have been served from the cleartext cache"

hdr "Controls"
login "$USR" "WRONG" REQUIRED \
	&& nok "wrong password ACCEPTED -- the hash is not really being verified" \
	|| ok  "wrong password rejected over TLS"

login "$USR" "$PW" REQUIRED \
	&& ok  "second TLS connection succeeded" \
	|| nok "second TLS connection failed"
C2="$(sha2cached)"
[[ "${C2:-0}" -gt 0 ]] 2>/dev/null \
	&& ok "counter rose to ${C2} -> repeat connection used the cache, confirming the counter tracks cache hits" \
	|| nok "counter did not rise on a repeat connection; the proof above is not meaningful"

# ---------------------------------------------------------------- done ---
hdr "Summary"
printf '  passed: %d\n  failed: %d\n' "$PASS" "$FAIL"
if [[ "$FAIL" -eq 0 ]]; then
	cat <<'EOS'

  CONCLUSION
    The Admin interface performs and completes caching_sha2_password full
    authentication against a caching_sha2-hashed credential, from a cold
    cache, with no mysql_users row present.

    Issue #5985 ask 2 -- "fix the Admin module's full-auth completion so a
    cleartext password received over TLS is verified against the stored
    credential" -- therefore describes behaviour that already works.
EOS
	exit 0
fi
echo; echo "  One or more assertions failed; see above."
exit 1
