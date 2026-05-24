/**
 * @file test_passthrough_auth_security-t.cpp
 * @brief End-to-end tests for the three security gates of pass-through
 *        authentication: TLS gate, username_pattern allowlist, and
 *        COM_CHANGE_USER rejection.
 *
 * Each gate is exercised with a positive and negative case so the test
 * actually proves the gate WORKS and isn't a no-op:
 *
 *   TLS gate (mysql-passthrough_auth_require_tls, default true):
 *     - require_tls=true + non-TLS client connect -> rejected
 *     - require_tls=false + same client connect   -> success
 *     If the gate were a no-op (always allow), the first attempt would
 *     also succeed and the differential disappears.
 *
 *   username_pattern (mysql-passthrough_auth_username_pattern, default ""):
 *     - pattern that does NOT match the test user      -> rejected
 *     - pattern that DOES   match the test user        -> success
 *     - invalid regex (deliberately broken)             -> rejected
 *     The third case validates the fail-safe deny path -- a malformed
 *     pattern must NOT default to allow-everything.
 *
 *   COM_CHANGE_USER (spec §5.4, commit d4569ee):
 *     - open a normal connection through proxy as cl.username
 *     - mysql_change_user() to the pass-through-eligible user with
 *       the real backend password
 *     - must be rejected (the spec says Phase 1 doesn't drive
 *       pass-through from CHANGE_USER)
 *     If process_pkt_COM_CHANGE_USER lacked the rejection, the empty-
 *     password row would grant passwordless CHANGE_USER (the §3.2
 *     bypass that f80a5f9 closed for the initial handshake path) and
 *     this assertion would fail.
 *
 * Spec reference: doc/internal/passthrough_authentication.md §3.2,
 * §5.4, §7.1, §7.4
 */
#include <cstring>
#include <string>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

static constexpr const char* TEST_USER       = "tap_pt_security_user";
static constexpr const char* TEST_BACKEND_PW = "s3cur1ty-3nd-2-3nd!";

static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static int do_query(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Helper: try a frontend connect, return mysql_errno (0 on success).
 *
 * @param req_auth_plugin Defaults to caching_sha2_password. Pass another
 *                        plugin name to exercise the non-caching_sha2
 *                        rejection in the security gates.
 */
static unsigned int try_connect(
	const CommandLine& cl, const char* user, const char* pass,
	const char* req_auth_plugin = "caching_sha2_password"
) {
	MYSQL* m = mysql_init(NULL);
	if (!m) return UINT_MAX;
	mysql_options(m, MYSQL_DEFAULT_AUTH, req_auth_plugin);
	const MYSQL* res = mysql_real_connect(
		m, cl.host, user, pass, NULL, cl.port, NULL, 0
	);
	const unsigned int err = res ? 0 : mysql_errno(m);
	mysql_close(m);
	return err;
}

/**
 * @brief SET + LOAD a single variable, returning EXIT_SUCCESS / FAILURE.
 *
 * Single-shot helper used by the gate-toggle sequences below where each
 * gate change must be visible to subsequent connect attempts.
 */
static int set_and_load(MYSQL* admin, const string& set_query) {
	if (do_query(admin, set_query) != EXIT_SUCCESS) return EXIT_FAILURE;
	return do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
}

int main() {
	CommandLine cl;

	/*
	 * Plan = total ok() calls. Counted from the body below.
	 *
	 *   Setup (5):
	 *     backend connect, admin connect, user provisioned,
	 *     mysql_users row inserted, base passthrough config applied
	 *
	 *   TLS gate (2):
	 *     [T1] require_tls=true + non-TLS connect -> rejected
	 *     [T2] require_tls=false -> same connect succeeds
	 *
	 *   username_pattern (3):
	 *     [P1] non-matching pattern -> rejected
	 *     [P2] matching pattern     -> success
	 *     [P3] invalid regex        -> rejected (fail-safe deny)
	 *
	 *   COM_CHANGE_USER (1):
	 *     [C1] CHANGE_USER to passthrough user -> rejected
	 *
	 *   Cleanup (2): DROP USER, restore globals
	 *
	 *   5 + 2 + 3 + 1 + 2 = 13.
	 */
	plan(13);

	if (cl.getEnv()) {
		diag("CommandLine getEnv() failed");
		return exit_status();
	}

	MYSQL* backend = mysql_init(NULL);
	ok(mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
			NULL, cl.mysql_port, NULL, 0) != NULL,
		"Connected to backend MySQL at %s:%d", cl.mysql_host, cl.mysql_port);

	MYSQL* admin = mysql_init(NULL);
	ok(mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0) != NULL,
		"Connected to ProxySQL admin at %s:%d", cl.admin_host, cl.admin_port);

	/* -------- backend user with caching_sha2_password -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	const bool user_ok =
		(do_query(backend,
			string("CREATE USER '") + TEST_USER + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + TEST_BACKEND_PW + "'") == EXIT_SUCCESS) &&
		(do_query(backend,
			string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'") == EXIT_SUCCESS);
	ok(user_ok, "Backend user '%s' provisioned", TEST_USER);

	/* -------- empty-password row + LOAD -------- */
	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	const bool row_ok =
		(do_query(admin,
			string("INSERT INTO mysql_users (username, password, default_hostgroup, active) "
				"VALUES ('") + TEST_USER + "', '', " + std::to_string(MYSQL8_HG) + ", 1)") == EXIT_SUCCESS) &&
		(do_query(admin, "LOAD MYSQL USERS TO RUNTIME") == EXIT_SUCCESS);
	ok(row_ok, "Empty-password mysql_users row inserted for '%s'", TEST_USER);

	/* -------- base pass-through configuration --------
	 *
	 * Everything DEFAULT except master gate on. Specific gates are
	 * toggled per-scenario. Note we keep require_tls at its default
	 * (true) here so the TLS scenario below tests it from a known
	 * state. */
	bool cfg_ok = true;
	{
		const vector<string> base_cfg {
			"SET mysql-passthrough_auth_enabled='true'",
			"SET mysql-passthrough_auth_empty_password='true'",
			"SET mysql-passthrough_auth_unknown_users='false'",
			"SET mysql-passthrough_auth_username_pattern=''",
			"SET mysql-default_authentication_plugin='caching_sha2_password'",
			"PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE",
			"LOAD MYSQL VARIABLES TO RUNTIME",
		};
		for (const string& q : base_cfg) {
			if (do_query(admin, q) != EXIT_SUCCESS) { cfg_ok = false; break; }
		}
	}
	ok(cfg_ok, "Base passthrough configuration applied");

	/* ============================================================
	 * TLS gate: require_tls=true blocks non-TLS, require_tls=false
	 * allows it.
	 *
	 * We don't set up client-side TLS in this test (the SSL fixture
	 * is non-trivial); instead we measure the DIFFERENTIAL. The
	 * client is configured identically in both attempts; only the
	 * server-side gate flips. If the gate is wired correctly, the
	 * connect must fail under require_tls=true and succeed under
	 * require_tls=false. A no-op gate would show both attempts
	 * succeed (regression in PPHR_verify_password's TLS check).
	 * ============================================================ */
	{
		set_and_load(admin, "SET mysql-passthrough_auth_require_tls='true'");
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[T1] TLS gate active + non-TLS client -> rejected "
			"(errno=%u, expected %u)", err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}
	{
		set_and_load(admin, "SET mysql-passthrough_auth_require_tls='false'");
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0,
			"[T2] TLS gate off + same non-TLS client -> success "
			"(errno=%u)", err);
	}

	/* ============================================================
	 * username_pattern allowlist.
	 *
	 * TEST_USER is "tap_pt_security_user". We pick three patterns:
	 *   [P1] "^app_.*$"           -- definitively does NOT match
	 *   [P2] "^tap_pt_security_.*$" -- definitively matches
	 *   [P3] "[unclosed bracket"  -- intentionally broken regex
	 *
	 * The fail-safe-deny semantics for [P3] are a critical defense:
	 * the pattern is operator-supplied and a typo must NOT default
	 * to allow-everything (that would silently re-open the gate the
	 * pattern exists to close). RE2::ok() returns false on a bad
	 * regex; username_allowed treats that as "not allowed".
	 *
	 * Each scenario flushes the cache first so the eligibility
	 * check is actually evaluated -- a cache hit would short-circuit
	 * the pattern check.
	 * ============================================================ */
	{
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		set_and_load(admin, "SET mysql-passthrough_auth_username_pattern='^app_.*$'");
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[P1] non-matching pattern '^app_.*$' rejects '%s' "
			"(errno=%u, expected %u)",
			TEST_USER, err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}
	{
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		set_and_load(admin, "SET mysql-passthrough_auth_username_pattern='^tap_pt_security_.*$'");
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0,
			"[P2] matching pattern '^tap_pt_security_.*$' allows '%s' "
			"(errno=%u)",
			TEST_USER, err);
	}
	{
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		/* "[" without matching "]" is a re2 syntax error. RE2::ok()
		 * returns false; username_allowed must treat that as deny. */
		set_and_load(admin, "SET mysql-passthrough_auth_username_pattern='[unclosed'");
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[P3] invalid regex '[unclosed' -> deny (fail-safe) "
			"(errno=%u, expected %u)",
			err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/* ============================================================
	 * COM_CHANGE_USER rejection (spec §5.4).
	 *
	 * Open a normal session through proxy using cl.username (the TAP
	 * fixture's regular user), then issue COM_CHANGE_USER to the
	 * pass-through-eligible TEST_USER with the REAL backend password.
	 *
	 * Phase 1 does not support driving the caching_sha2_password
	 * full-auth exchange from a mid-session CHANGE_USER (the protocol
	 * state machine in PPHR_passthrough_init assumes a fresh client
	 * handshake). Commit d4569ee added an explicit rejection in
	 * process_pkt_COM_CHANGE_USER. Without that rejection, the
	 * existing
	 *
	 *   if (pass_len == 0 && strlen(password) == 0) ret = true;
	 *
	 * branch lower in process_pkt_COM_CHANGE_USER would grant
	 * passwordless CHANGE_USER access to the empty-pw row -- a
	 * silent §3.2 bypass through a different code path than the
	 * initial-handshake one (which f80a5f9 already closed).
	 *
	 * Setup before CHANGE_USER:
	 *   - permissive username_pattern so the gate isn't the reason
	 *     for the reject (we want process_pkt_COM_CHANGE_USER's
	 *     own rejection, not the eligibility short-circuit)
	 *   - cache flushed
	 *   - require_tls left at false (set above) -- CHANGE_USER
	 *     doesn't drive an AuthMoreData{0x04} exchange in Phase 1
	 *     either way; the rejection happens before any plugin work
	 *
	 * Assertion: mysql_change_user returns non-zero (failure).
	 * ============================================================ */
	{
		set_and_load(admin, "SET mysql-passthrough_auth_username_pattern=''");
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		MYSQL* m = mysql_init(NULL);
		const MYSQL* res = mysql_real_connect(
			m, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0
		);
		if (!res) {
			diag("Pre-CHANGE_USER connect as '%s' failed: %s", cl.username, mysql_error(m));
			ok(false, "[C1] Pre-CHANGE_USER fixture connection (skipped: connect failed)");
		} else {
			const int rc = mysql_change_user(m, TEST_USER, TEST_BACKEND_PW, NULL);
			const unsigned int err = mysql_errno(m);
			ok(rc != 0 && err == ER_ACCESS_DENIED_ERROR,
				"[C1] CHANGE_USER to passthrough user '%s' rejected "
				"(rc=%d, errno=%u, expected %u)",
				TEST_USER, rc, err, (unsigned)ER_ACCESS_DENIED_ERROR);
		}
		mysql_close(m);
	}

	/* -------- cleanup -------- */
	{
		const int rc = do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
		ok(rc == EXIT_SUCCESS, "Cleanup: DROP USER on backend");
	}
	{
		int rc = EXIT_SUCCESS;
		rc |= do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
		rc |= do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		rc |= do_query(admin, "LOAD MYSQL USERS TO RUNTIME");
		rc |= do_query(admin, "SET mysql-passthrough_auth_enabled='false'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_require_tls='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_username_pattern=''");
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: mysql_users + globals restored");
	}

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
