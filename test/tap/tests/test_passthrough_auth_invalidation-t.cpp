/**
 * @file test_passthrough_auth_invalidation-t.cpp
 * @brief End-to-end test for backend-rejection cache invalidation
 *        (spec §8.4) -- P2-D from the round-3 review.
 *
 * The pass-through cache holds the cleartext password ProxySQL learned
 * from a successful backend probe. When the backend's password later
 * rotates (admin runs ALTER USER on the upstream server), the cached
 * cleartext is stale. The next query that needs a fresh backend
 * connection will use the stale cleartext, the backend will reject
 * with @c ER_ACCESS_DENIED_ERROR (1045), and the hook in
 * @c handler_again___status_CONNECTING_SERVER must:
 *
 *   - evict the stale cache entry so subsequent connects re-probe
 *     against the new password, AND
 *   - bump the @c cache_invalidations counter (gated on the session's
 *     @c passthrough_credential flag, per commit N4).
 *
 * Sequence the test follows:
 *
 *   1. Provision backend user with @c old_password.
 *   2. Configure passthrough; first connect drives a real probe and
 *      caches @c old_password.
 *   3. Read @c cache_invalidations and the cache row -- baseline.
 *   4. ALTER USER on the backend to @c new_password.
 *   5. Open a fresh client connection through ProxySQL using the same
 *      @c old_password. The pass-through cache HITS (frontend
 *      verification succeeds against the cached cleartext) and the
 *      session is marked @c passthrough_credential.
 *   6. Issue SELECT 1 over that session. ProxySQL needs a backend
 *      connection; the probe connection from step 2 was closed (one-
 *      shot, not pooled), so the pool is empty and a fresh backend
 *      conn is required. The connection attempt uses @c old_password
 *      and the backend now rejects with 1045.
 *   7. Re-read @c cache_invalidations and the cache row:
 *      cache_invalidations must have incremented AND the cache entry
 *      for the user must be gone.
 *
 * Step 6 is the load-bearing path. If the pool happens to have a
 * usable connection (e.g. parallel test load), the query won't trigger
 * the eviction hook and the test would yield a false negative -- the
 * counter delta assertion catches that case explicitly (delta == 0
 * → fail).
 */
#include <cstring>
#include <string>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

static constexpr const char* TEST_USER = "tap_pt_invalidation_user";
static constexpr const char* OLD_PW    = "0ld-passw0rd-rot4t10n!";
static constexpr const char* NEW_PW    = "n3w-passw0rd-rot4t10n!";

static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static int do_query(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int64_t read_metric(MYSQL* admin, const string& name) {
	const string q =
		"SELECT metric_value FROM stats_mysql_passthrough_auth_metrics "
		"WHERE metric_name='" + name + "'";
	if (mysql_query(admin, q.c_str())) return -1;
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	int64_t v = (row && row[0]) ? atoll(row[0]) : -1;
	mysql_free_result(res);
	return v;
}

static int cache_entry_count_for(MYSQL* admin, const string& user) {
	const string q =
		"SELECT COUNT(*) FROM stats_mysql_passthrough_auth_cache WHERE username='" + user + "'";
	if (mysql_query(admin, q.c_str())) return -1;
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	int n = (row && row[0]) ? atoi(row[0]) : -1;
	mysql_free_result(res);
	return n;
}

/**
 * @brief Open a frontend session, run a query, and report both the
 *        connect errno and the query errno.
 *
 * The query is what triggers the backend-pool acquisition, so a
 * frontend connect that succeeds via cache hit AND a backend 1045
 * during query execution will produce @c { 0, 1045 }.
 */
static std::pair<unsigned int, unsigned int> connect_and_query(
	const CommandLine& cl, const char* user, const char* pw
) {
	MYSQL* m = mysql_init(NULL);
	mysql_options(m, MYSQL_DEFAULT_AUTH, "caching_sha2_password");
	/*
	 * CLIENT_SSL is required on the frontend leg for caching_sha2_password
	 * full-auth: ProxySQL's PPHR_passthrough_init dispatches via the
	 * cleartext-over-TLS path only (see e2e-t comment for the protocol
	 * details). Pattern mirrors the other passthrough tests in
	 * mysql84-g4.
	 */
	mysql_ssl_set(m, NULL, NULL, NULL, NULL, NULL);
	const MYSQL* res = mysql_real_connect(m, cl.host, user, pw, NULL, cl.port, NULL, CLIENT_SSL);
	if (!res) {
		const unsigned int err = mysql_errno(m);
		mysql_close(m);
		return { err, 0 };
	}
	const int qrc = mysql_query(m, "SELECT 1");
	const unsigned int qerr = qrc ? mysql_errno(m) : 0;
	if (!qrc) {
		MYSQL_RES* r = mysql_store_result(m);
		if (r) mysql_free_result(r);
	}
	mysql_close(m);
	return { 0, qerr };
}

int main() {
	CommandLine cl;

	/*
	 * Plan = total ok() calls:
	 *   Setup (4):
	 *     backend connect, admin connect, user provisioned,
	 *     passthrough configured
	 *   [1] First connect (1)
	 *   [2] ALTER USER on backend (1)
	 *   [3] Triple assertion -- frontend handshake / SELECT 1 1045 /
	 *       cache_invalidations + cache empty (3 ok() lines: [3a],
	 *       [3b], [3c])
	 *   Cleanup (2): DROP USER, restore globals
	 *
	 *   4 + 1 + 1 + 3 + 2 = 11.
	 */
	plan(11);

	if (cl.getEnv()) {
		return exit_status();
	}

	MYSQL* backend = mysql_init(NULL);
	ok(mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
			NULL, cl.mysql_port, NULL, 0) != NULL,
		"Connected to backend MySQL");

	MYSQL* admin = mysql_init(NULL);
	ok(mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0) != NULL,
		"Connected to ProxySQL admin");

	/*
	 * Defensive: bring all servers in MYSQL8_HG back to ONLINE before
	 * we begin. This test (and several siblings in mysql84-g4) toggles
	 * status='OFFLINE_HARD' on the hostgroup during scenario [3] to
	 * force a backend rotation. If a prior run of this test crashed,
	 * was killed, or aborted mid-scenario before reaching its cleanup
	 * block, the hostgroup may already be OFFLINE_HARD in
	 * mysql_servers -- in which case step [1] below would fail with
	 * "ProxySQL Error: Max connect timeout" before we even reach the
	 * intended assertion. Re-applying ONLINE is idempotent and only
	 * affects state we ourselves own (the test's TEST_USER + this
	 * dedicated HG). LOAD MYSQL SERVERS TO RUNTIME publishes the
	 * change to the data plane so subsequent probes see live backends.
	 */
	do_query(admin,
		string("UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* -------- backend user with old password -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	const bool user_ok =
		(do_query(backend,
			string("CREATE USER '") + TEST_USER + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + OLD_PW + "'") == EXIT_SUCCESS) &&
		(do_query(backend,
			string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'") == EXIT_SUCCESS);
	ok(user_ok, "Backend user provisioned with OLD password");

	/* -------- empty-pw row + passthrough config -------- */
	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	do_query(admin,
		string("INSERT INTO mysql_users (username, password, default_hostgroup, active) VALUES ('")
		+ TEST_USER + "', '', " + std::to_string(MYSQL8_HG) + ", 1)");
	do_query(admin, "LOAD MYSQL USERS TO RUNTIME");

	bool cfg_ok = true;
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_enabled='true'") == EXIT_SUCCESS);
	/* require_tls left at default 'true'; test's connect_and_query wires CLIENT_SSL. See e2e-t for the protocol rationale. */
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_require_tls='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_empty_password='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-default_authentication_plugin='caching_sha2_password'") == EXIT_SUCCESS);
	/*
	 * Isolate this test from the per-IP failure counter pollution
	 * that may carry over from the rate-limit test (R4-B5). The two
	 * tests share TAP group mysql84-g4 and the same client IP from
	 * which ratelimit-t intentionally drives many failures. Setting
	 * the caps very high here means cross-test pollution can't
	 * lock out our first probe in step 1. Cleanup restores defaults.
	 */
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='10000'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10000'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == EXIT_SUCCESS);
	ok(cfg_ok, "Pass-through configured (failure caps raised for test isolation)");

	/* ============================================================
	 * Step 1 -- first connect probes & caches OLD password.
	 * ============================================================ */
	{
		const auto [cerr, qerr] = connect_and_query(cl, TEST_USER, OLD_PW);
		ok(cerr == 0 && qerr == 0,
			"[1] First connect with OLD password succeeds "
			"(connect_errno=%u, query_errno=%u)", cerr, qerr);
	}

	/* ============================================================
	 * Step 2 -- ALTER USER on backend rotates to NEW password,
	 *           AND force the proxy's pool to drop any cached backend
	 *           connection auth'd with OLD_PW.
	 *
	 * The previous version of this test omitted the pool drain. Step 1's
	 * connect_and_query() ran a SELECT 1 which acquired a backend
	 * connection from the pool, used it, and returned it to the pool.
	 * That pooled connection is auth'd with OLD_PW and remains usable
	 * even after the backend rotates the password (the backend doesn't
	 * tear down already-authenticated connections on ALTER USER). When
	 * step 3 then runs SELECT 1, the proxy may serve the still-valid
	 * pooled connection and NEVER attempt a fresh handshake -- which
	 * means the ER 1045 eviction hook never fires and the test would
	 * yield a false negative on healthy code (the R4-B3 finding from
	 * the round-4 test-quality subagent).
	 *
	 * The reliable way to force pool drain in ProxySQL is to mark every
	 * server in the target hostgroup OFFLINE_HARD, LOAD MYSQL SERVERS
	 * TO RUNTIME (which destroys pool connections to those servers),
	 * then flip back to ONLINE + LOAD. After this dance, step 3's
	 * SELECT 1 is guaranteed to require a fresh backend handshake
	 * because the pool is empty.
	 * ============================================================ */
	{
		const string alter =
			string("ALTER USER '") + TEST_USER + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + NEW_PW + "'";
		const string drain_seq =
			string("UPDATE mysql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=") + std::to_string(MYSQL8_HG);
		const string undrain_seq =
			string("UPDATE mysql_servers SET status='ONLINE' WHERE hostgroup_id=") + std::to_string(MYSQL8_HG);
		int rc = EXIT_SUCCESS;
		rc |= do_query(backend, alter);
		rc |= do_query(admin, drain_seq);
		rc |= do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		rc |= do_query(admin, undrain_seq);
		rc |= do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
		ok(rc == EXIT_SUCCESS,
			"[2] ALTER USER + pool drain (OFFLINE_HARD/LOAD/ONLINE/LOAD)");
	}

	/*
	 * Capture baseline counter + cache state BEFORE the
	 * invalidation-triggering connect.
	 */
	const int64_t inv_before = read_metric(admin, "cache_invalidations");
	const int cache_before   = cache_entry_count_for(admin, TEST_USER);

	/* ============================================================
	 * Step 3 -- new client connects with OLD password.
	 *
	 * Frontend: cache HIT (cleartext is OLD_PW which is what the
	 * client also sent; PPHR_6auth2 verifies the scramble against the
	 * cached cleartext and accepts). Session is marked
	 * @c passthrough_credential = true.
	 *
	 * Backend: connection pool has no entries for this user (the
	 * probe in step 1 was a one-shot mysql_real_connect, closed
	 * immediately, never pooled). So the SELECT 1 triggers a fresh
	 * backend connection attempt using @c userinfo->password (OLD_PW
	 * from the cache). The backend rejects with 1045 because it now
	 * expects NEW_PW.
	 *
	 * The 1045 hook in handler_again___status_CONNECTING_SERVER:
	 *   - sees @c sess->passthrough_credential == true,
	 *   - calls @c GloMyPTAuthCache->evict() (returns true since the
	 *     entry exists),
	 *   - bumps @c cache_invalidations.
	 *
	 * The client gets a 1045 errno on SELECT 1. That's expected.
	 * ============================================================ */
	{
		const auto [cerr, qerr] = connect_and_query(cl, TEST_USER, OLD_PW);
		/* cerr should be 0: frontend handshake succeeds because the
		 * cache hit lets PPHR_6auth2 verify the scramble against the
		 * cached cleartext (no backend involvement at handshake).
		 * qerr should be 1045: SELECT 1 forces a fresh backend conn
		 * with the stale cleartext; backend rejects. */
		ok(cerr == 0,
			"[3a] Frontend handshake succeeds via cache hit "
			"(connect_errno=%u)", cerr);
		ok(qerr == ER_ACCESS_DENIED_ERROR,
			"[3b] SELECT 1 fails with 1045 (stale cached cleartext) "
			"(query_errno=%u, expected %u)",
			qerr, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/*
	 * Allow a few microseconds for the eviction hook to run on the
	 * worker thread before reading state. In practice the eviction
	 * is synchronous with the 1045 handling, so the next admin query
	 * already sees the result. Add a small retry budget for
	 * robustness on busy CI.
	 */
	int64_t inv_after = read_metric(admin, "cache_invalidations");
	int cache_after   = cache_entry_count_for(admin, TEST_USER);
	for (int i = 0; i < 20 && (inv_after <= inv_before || cache_after != 0); ++i) {
		usleep(50000);
		inv_after  = read_metric(admin, "cache_invalidations");
		cache_after = cache_entry_count_for(admin, TEST_USER);
	}
	ok(inv_after >= inv_before + 1 && cache_after == 0,
		"[3c] cache_invalidations++ AND cache entry evicted "
		"(invalidations: %lld -> %lld; cache rows for user: %d -> %d)",
		(long long)inv_before, (long long)inv_after,
		cache_before, cache_after);

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
		rc |= do_query(admin, "SET mysql-passthrough_auth_empty_password='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_require_tls='true'");
		/* Restore the failure caps we raised in setup so the next test
		 * inherits the documented defaults. */
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='3'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10'");
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: globals restored");
	}

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
