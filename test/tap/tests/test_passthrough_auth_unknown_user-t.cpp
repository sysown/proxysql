/**
 * @file test_passthrough_auth_unknown_user-t.cpp
 * @brief End-to-end test for the unknown-user pass-through path.
 *
 * Distinct from test_passthrough_auth_e2e-t.cpp which covers the
 * empty-password ROW case: here we exercise the case where the user does
 * NOT exist in mysql_users at all and pass-through is gated by
 * @c mysql-passthrough_auth_unknown_users=true. Defaults (default_hostgroup,
 * default_schema, schema_locked, transaction_persistent, fast_forward,
 * max_connections) are synthesized from @c mysql-passthrough_default_* globals
 * each connect (spec §3.5).
 *
 * Critically, this test verifies the fix from commit c683943
 * ("unknown-user cache hit no longer clobbers state"): a cache-hit
 * reconnect must still route queries correctly to the synthesized
 * default_hostgroup. Before that fix, PPHR_5passwordTrue would
 * overwrite the session's default_hostgroup with the value from a
 * default-constructed account_details_t (i.e. 0). The test catches
 * the regression by running a SELECT 1 through the reconnect path; if
 * default_hostgroup were silently reset to 0 and HG 0 isn't a valid
 * route, the query would fail.
 *
 * Spec reference: doc/internal/passthrough_authentication.md §3.5, §8.2
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

/**
 * @brief Test fixture user (created on backend, NOT in mysql_users).
 *
 * Distinct name from the empty-pw e2e test so the two can coexist in the
 * same backend without DROP-USER races if CI ever runs them concurrently.
 */
static constexpr const char* TEST_USER       = "tap_pt_unknown_user";
static constexpr const char* TEST_BACKEND_PW = "unkn0wn-3nd-2-3nd!";

/**
 * @brief MySQL 8+ backend hostgroup (overridable via env, same convention
 * as reg_test_4935-caching_sha2-t).
 */
static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static int do_query(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int cache_entry_count(MYSQL* admin) {
	if (mysql_query(admin, "SELECT COUNT(*) FROM stats_mysql_passthrough_auth_cache")) {
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	int n = (row && row[0]) ? atoi(row[0]) : -1;
	mysql_free_result(res);
	return n;
}

/**
 * @brief Read the hostgroup_probed column for a specific user from the
 * stats virtual table.
 *
 * Returns -1 if the row is missing or the query fails. This is the
 * critical assertion for the unknown-user path: the value must be the
 * configured @c mysql-passthrough_default_hg, NOT zero.
 */
static int cache_hostgroup_probed(MYSQL* admin, const string& user) {
	const string q =
		"SELECT hostgroup_probed FROM stats_mysql_passthrough_auth_cache "
		"WHERE username='" + user + "'";
	if (mysql_query(admin, q.c_str())) return -1;
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	int hg = (row && row[0]) ? atoi(row[0]) : -1;
	mysql_free_result(res);
	return hg;
}

/**
 * @brief Try a frontend connect AND run SELECT 1 over the resulting
 * connection.
 *
 * Returning the mysql_errno from the failure path isn't enough on its
 * own to validate the unknown-user routing path: a connect can succeed
 * (PPHR_verify_password returns true via cache hit) while query routing
 * is broken because session->default_hostgroup got clobbered. SELECT 1
 * forces a backend acquisition, so a HG-0-when-it-should-be-HG-N routing
 * bug would surface as either a connection-pool failure or a wrong
 * @c @@hostname depending on infra. We treat any query failure as a test
 * fail to make the regression visible.
 *
 * @return @c std::pair { connect_errno, query_errno } where 0/0 means
 *         success. A failure at connect leaves query_errno at 0 (we
 *         don't run the query).
 */
static std::pair<unsigned int, unsigned int> connect_and_select_1(
	const CommandLine& cl, const char* user, const char* pass
) {
	MYSQL* m = mysql_init(NULL);
	if (!m) return { UINT_MAX, 0 };
	mysql_options(m, MYSQL_DEFAULT_AUTH, "caching_sha2_password");
	/*
	 * TLS is mandatory on the frontend leg for caching_sha2_password
	 * full-auth -- ProxySQL's AuthMoreData{0x04} reply forces the client
	 * to send its cleartext, and PPHR_passthrough_init does not implement
	 * the RSA-encrypted (0x02 public-key-request) branch. See
	 * test_passthrough_auth_e2e-t.cpp for the full explanation; this
	 * comment block intentionally mirrors that test's posture.
	 */
	mysql_ssl_set(m, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(m, cl.host, user, pass, NULL, cl.port, NULL, CLIENT_SSL)) {
		const unsigned int err = mysql_errno(m);
		diag("Frontend connect for user='%s' failed: errno=%u msg='%s'",
			user, err, mysql_error(m));
		mysql_close(m);
		return { err, 0 };
	}
	const int qrc = mysql_query(m, "SELECT 1");
	const unsigned int qerr = qrc ? mysql_errno(m) : 0;
	if (qrc) {
		diag("SELECT 1 for user='%s' failed: errno=%u msg='%s'",
			user, qerr, mysql_error(m));
	} else {
		MYSQL_RES* r = mysql_store_result(m);
		if (r) mysql_free_result(r);
	}
	mysql_close(m);
	return { 0, qerr };
}

int main() {
	CommandLine cl;

	/*
	 * Plan = total ok() calls below.
	 *
	 *   Setup (8):
	 *     backend connect, admin connect, backend user created,
	 *     mysql_users row absent (verified), HG 0 fenced OFFLINE_HARD,
	 *     passthrough enabled, passthrough_default_hg verified,
	 *     cache empty
	 *
	 *   [1] First connect probes + caches (2): connect/query ok, n=1
	 *   [2] Cache entry's hostgroup_probed matches default_hg (1)
	 *   [3] Reconnect: cache hit AND query still routes correctly (1)
	 *   [4] With unknown_users=false the same user is rejected (1)
	 *
	 *   Cleanup (3): DROP USER, restore HG 0, restore globals
	 *
	 *   8 + 2 + 1 + 1 + 1 + 3 = 16.
	 */
	plan(16);

	if (cl.getEnv()) {
		diag("CommandLine getEnv() failed");
		return exit_status();
	}

	MYSQL* backend = mysql_init(NULL);
	const MYSQL* bcr = mysql_real_connect(
		backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
		NULL, cl.mysql_port, NULL, 0
	);
	ok(bcr != NULL, "Connected to backend MySQL at %s:%d", cl.mysql_host, cl.mysql_port);
	if (!bcr) return exit_status();

	MYSQL* admin = mysql_init(NULL);
	const MYSQL* acr = mysql_real_connect(
		admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0
	);
	ok(acr != NULL, "Connected to ProxySQL admin at %s:%d", cl.admin_host, cl.admin_port);
	if (!acr) { mysql_close(backend); return exit_status(); }

	/*
	 * Defensive: restore HG 0 and MYSQL8_HG to ONLINE before this test
	 * begins. The mysql84-g4 group runs this test alongside
	 * invalidation-t (which toggles MYSQL8_HG to OFFLINE_HARD) and the
	 * unknown_user-t fence block below (which toggles HG 0 to
	 * OFFLINE_HARD). If a prior sibling test crashed or was killed
	 * before its cleanup ran, mysql_servers may already have
	 * status='OFFLINE_HARD' on one or both of those hostgroups,
	 * leaving every backend in this group unreachable and turning
	 * later ok() probes into spurious connect-timeout failures with no
	 * relationship to the regression we're actually trying to catch.
	 *
	 * Re-applying ONLINE is idempotent for the healthy case and only
	 * mutates state we own (HG 0 is the fallback seeded by the infra
	 * and exclusively toggled by this test; MYSQL8_HG is the writer
	 * group exclusively toggled by invalidation-t). The fence block
	 * below immediately re-sets HG 0 back to OFFLINE_HARD -- this
	 * restore-then-fence pattern guarantees a known starting state
	 * regardless of how the prior run terminated.
	 */
	do_query(admin, "UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=0");
	do_query(admin,
		string("UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* -------- backend user with caching_sha2_password -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	bool user_ok =
		(do_query(backend,
			string("CREATE USER '") + TEST_USER + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + TEST_BACKEND_PW + "'") == EXIT_SUCCESS) &&
		(do_query(backend,
			string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'") == EXIT_SUCCESS);
	ok(user_ok, "Backend user '%s' provisioned with caching_sha2_password", TEST_USER);

	/* -------- ensure NO row in mysql_users (this is the whole point) -------- */
	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	do_query(admin, "LOAD MYSQL USERS TO RUNTIME");
	{
		const string q =
			string("SELECT COUNT(*) FROM mysql_users WHERE username='") + TEST_USER + "'";
		int count_after_delete = -1;
		if (mysql_query(admin, q.c_str()) == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && row[0]) count_after_delete = atoi(row[0]);
			if (res) mysql_free_result(res);
		}
		ok(count_after_delete == 0,
			"mysql_users has NO row for '%s' (count=%d)", TEST_USER, count_after_delete);
	}

	/*
	 * Fence hostgroup 0 OFFLINE_HARD before the test runs.
	 *
	 * The mysql84 test infra (test/infra/infra-mysql84/bin/
	 * docker-proxy-post.bash) seeds a fallback mysql_servers row into
	 * HG 0 that points at the same backend as the writer HG. Without
	 * fencing it, a clobber-to-HG-0 regression in
	 * PPHR_5passwordTrue (the very bug we're guarding against in
	 * scenarios [1] and [3]) would route SELECT 1 to HG 0 and SUCCEED
	 * -- the test would pass while the regression is live.
	 *
	 * By marking every HG-0 server OFFLINE_HARD just for the duration
	 * of this test, any routing to HG 0 deterministically fails: the
	 * connect pool can't acquire a server, and the query returns an
	 * error. So a clobber regression will now surface as a query
	 * failure on the next ok() rather than silently passing. Cleanup
	 * at the end restores HG 0 to its prior state.
	 */
	{
		const int fence_rc =
			do_query(admin, "UPDATE mysql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=0") |
			do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		ok(fence_rc == EXIT_SUCCESS,
			"HG 0 fenced OFFLINE_HARD (catches clobber-to-HG-0 regressions)");
	}

	/*
	 * Raise failure caps very high for the duration of this test
	 * (cleanup restores defaults). This test shares mysql84-g4 with
	 * ratelimit-t (which intentionally drives MANY failures from the
	 * same client IP to trigger lockout) and metrics-t / security-t
	 * (which also drive failed probes). On default caps (3/user, 10/IP)
	 * the per-IP counter spills over from a sibling test and locks out
	 * our first unknown-user probe before it ever reaches the cache,
	 * causing spurious "lockout" errors unrelated to the unknown-user
	 * flow under test. Raising caps to 10000 makes cross-test pollution
	 * non-issue. Mirrors the pattern in invalidation-t.
	 */
	/* -------- enable unknown_users pass-through -------- */
	const vector<string> enable_queries {
		"SET mysql-passthrough_auth_enabled='true'",
		/*
		 * Leave require_tls at the default 'true'; the test's frontend
		 * connect helper (connect_and_select_1) now wires CLIENT_SSL so
		 * the gate is satisfied. See e2e-t for the full TLS rationale.
		 */
		"SET mysql-passthrough_auth_require_tls='true'",
		"SET mysql-passthrough_auth_unknown_users='true'",
		"SET mysql-passthrough_auth_empty_password='false'",
		"SET mysql-passthrough_auth_max_failures_per_user='10000'",
		"SET mysql-passthrough_auth_max_failures_per_ip='10000'",
		string("SET mysql-passthrough_default_hg='") + std::to_string(MYSQL8_HG) + "'",
		"SET mysql-default_authentication_plugin='caching_sha2_password'",
		"PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};
	bool cfg_ok = true;
	for (const string& q : enable_queries) {
		if (do_query(admin, q) != EXIT_SUCCESS) { cfg_ok = false; break; }
	}
	ok(cfg_ok, "unknown_users=true, default_hg=%u, TLS gate off", MYSQL8_HG);

	/*
	 * Ensure the target hostgroup (passthrough_default_hg) has use_ssl=1
	 * so the passthrough probe negotiates TLS to the backend.
	 *
	 * Same root cause as the other mysql84-g4 passthrough tests:
	 * the probe path only does TLS if MySrvC->use_ssl is true. The
	 * dbdeployer mysql84+ infras used by this group do not set it by
	 * default. Without this, the "first connect for unknown user" and
	 * the cache-hit SELECT 1 scenarios would see probe failures instead
	 * of success.
	 *
	 * We apply this right after setting passthrough_default_hg and
	 * before the first probe.
	 */
	do_query(admin,
		string("UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* Confirm the routing default we just set is what we expect to see in
	 * stats_mysql_passthrough_auth_cache.hostgroup_probed below. */
	{
		string val;
		if (mysql_query(admin,
			"SELECT variable_value FROM global_variables "
			"WHERE variable_name='mysql-passthrough_default_hg'") == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && row[0]) val = row[0];
			if (res) mysql_free_result(res);
		}
		ok(val == std::to_string(MYSQL8_HG),
			"mysql-passthrough_default_hg='%u' (got '%s')", MYSQL8_HG, val.c_str());
	}

	ok(cache_entry_count(admin) == 0, "Cache empty after FLUSH");

	/* ============================================================
	 * Scenario 1: first connect probes & caches AND query routes correctly.
	 *
	 * Real-test note: if PPHR_5passwordTrue clobbered session->default_hostgroup
	 * on the synthesis path (the #1.2 bug), the connect would succeed but
	 * the subsequent SELECT 1 might end up routed to HG 0 (which probably
	 * has no backend in this test infra) and FAIL. Running both connect
	 * AND a query is the load-bearing assertion here.
	 * ============================================================ */
	{
		const auto [cerr, qerr] = connect_and_select_1(cl, TEST_USER, TEST_BACKEND_PW);
		ok(cerr == 0 && qerr == 0,
			"[1] First connect + SELECT 1 succeed (connect_errno=%u, query_errno=%u)",
			cerr, qerr);
		ok(cache_entry_count(admin) == 1,
			"[1] Cache populated after first probe");
	}

	/* ============================================================
	 * Scenario 2: cache entry's hostgroup_probed equals
	 * mysql-passthrough_default_hg.
	 *
	 * This is the direct check that the probe routed to the synthesized
	 * hostgroup, not to HG 0. The handler stamps target_hg into
	 * passthrough_entry_view::hostgroup_probed on insert (see
	 * MySQL_Session.cpp ~ line "GloMyPTAuthCache->insert(... target_hg)").
	 * If synthesis was broken target_hg would be 0 and this assertion
	 * would fail cleanly.
	 * ============================================================ */
	{
		const int hg = cache_hostgroup_probed(admin, TEST_USER);
		ok(hg == static_cast<int>(MYSQL8_HG),
			"[2] cache.hostgroup_probed = passthrough_default_hg "
			"(got %d, expected %u)", hg, MYSQL8_HG);
	}

	/* ============================================================
	 * Scenario 3: reconnect hits cache AND still routes queries.
	 *
	 * This is the regression net for the #1.2 cache-hit-clobber fix.
	 * Without that fix, the cache-hit path falls through to
	 * PPHR_5passwordTrue, which copies a default-constructed
	 * account_details_t onto the session -- including default_hostgroup=0,
	 * transaction_persistent=false, schema_locked=false, etc. The connect
	 * would succeed (verification passes against the cached cleartext)
	 * but the SELECT 1 below would route to HG 0 and fail.
	 *
	 * Running the query is what makes this a real test rather than a
	 * tautology over the cache state.
	 * ============================================================ */
	{
		const auto [cerr, qerr] = connect_and_select_1(cl, TEST_USER, TEST_BACKEND_PW);
		ok(cerr == 0 && qerr == 0,
			"[3] Cache-hit reconnect + SELECT 1 succeed "
			"(connect_errno=%u, query_errno=%u) -- guards against the "
			"PPHR_5passwordTrue clobber regression",
			cerr, qerr);
	}

	/* ============================================================
	 * Scenario 4: when unknown_users=false, the same connection
	 * attempt must be rejected.
	 *
	 * Flush the cache first so the attempt actually has to go through
	 * the eligibility check (rather than hitting cache and succeeding).
	 * Then disable unknown_users. The connect must fail with 1045 --
	 * a successful connection here would mean either:
	 *   - the gate is being ignored (regression in PPHR_verify_password's
	 *     eligibility predicate), or
	 *   - the cache still has the entry (regression in the flush command).
	 * ============================================================ */
	{
		const int flush_rc = do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		const int n = cache_entry_count(admin);
		const int set_rc =
			do_query(admin, "SET mysql-passthrough_auth_unknown_users='false'") |
			do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		const auto [cerr, qerr] = connect_and_select_1(cl, TEST_USER, TEST_BACKEND_PW);
		ok(flush_rc == EXIT_SUCCESS && n == 0
		   && set_rc == EXIT_SUCCESS
		   && cerr == ER_ACCESS_DENIED_ERROR,
			"[4] With unknown_users=false the same user is rejected "
			"(flush_rc=%d, cache_n=%d, set_rc=%d, connect_errno=%u, "
			"expected=%u)",
			flush_rc, n, set_rc, cerr, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/* -------- cleanup: non-short-circuiting to ensure all queries run -------- */
	{
		const int rc = do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
		ok(rc == EXIT_SUCCESS, "Cleanup: DROP USER on backend");
	}
	{
		/*
		 * Restore HG 0 to ONLINE so any other test that shares this
		 * fixture and depends on the infra-seeded HG-0 fallback row
		 * isn't poisoned by our fencing.
		 */
		int rc = EXIT_SUCCESS;
		rc |= do_query(admin, "UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=0");
		rc |= do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: HG 0 restored to ONLINE");
	}
	{
		int rc = EXIT_SUCCESS;
		rc |= do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		rc |= do_query(admin, "SET mysql-passthrough_auth_enabled='false'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_unknown_users='false'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_empty_password='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_require_tls='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='3'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10'");
		rc |= do_query(admin, "SET mysql-passthrough_default_hg='0'");
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: globals restored");
	}

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
