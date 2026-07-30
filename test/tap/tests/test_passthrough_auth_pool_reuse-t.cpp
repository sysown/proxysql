/**
 * @file test_passthrough_auth_pool_reuse-t.cpp
 * @brief Adversarial test for the pass-through "force-new" probe invariant.
 *
 * This test guards the single load-bearing correctness claim of the
 * pass-through design: a pass-through backend probe MUST acquire a
 * FRESH backend connection (get_MyConn_from_pool(..., ff=true)) and
 * actually authenticate the borrowed credential against the backend --
 * it must NEVER be satisfied by a connection already sitting idle in the
 * pool.
 *
 * Why this matters
 * ----------------
 * ProxySQL's connection pool reuses backend connections keyed by
 * USERNAME only: requires_CHANGE_USER() compares the username and
 * match_tracked_options() compares client capability flags -- neither
 * checks the password. So a warm pooled connection authenticated for
 * `alice` with the CORRECT password X is, structurally, a candidate to
 * satisfy a request for `alice`. If the probe path ever reused such a
 * connection, a client presenting `alice` + a WRONG password Y would be
 * handed the already-authenticated connection and let in WITHOUT the
 * wrong password ever being validated -- a silent authentication
 * bypass. The `ff=true` (force-new) acquisition in
 * handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT is what
 * prevents this; see doc/internal/passthrough_authentication.md §6.3.
 *
 * The existing test_passthrough_auth_e2e-t proves wrong passwords are
 * rejected on a COLD cache. It does NOT prove they are rejected when a
 * warm, correctly-authenticated pooled connection for the same user is
 * available to be (mis)reused. That warm-pool window is exactly where a
 * force-new regression would hide, and it is what this test constructs
 * deliberately.
 *
 * Attack shape reproduced
 * -----------------------
 *   1. Legitimate client connects as U with the REAL password over TLS.
 *      The probe succeeds, U's credential is cached, and a backend
 *      connection authenticated as U/REAL is returned to the pool.
 *   2. Flush ONLY the pass-through credential cache for U (the pooled
 *      backend connection is untouched). Now the next connect for U
 *      cannot fast-path on the cache -- it MUST re-probe -- while a warm
 *      U/REAL connection is sitting free in the pool.
 *   3. Attacker connects as U with a WRONG password over TLS.
 *      Correct behavior: force-new probe -> backend rejects (1045) ->
 *      generic access denied. A force-new regression would instead reuse
 *      the warm U/REAL connection and return errno 0 (BYPASS).
 *   4. Positive control: U with the REAL password still succeeds, proving
 *      the deny in step 3 was password-specific, not a blanket breakage.
 *
 * Requires a MySQL 8+ backend (caching_sha2_password). Registered in the
 * mysql84+/mysql9x groups alongside the other pass-through e2e tests.
 *
 * Spec reference: doc/internal/passthrough_authentication.md §6.3, §11.1
 */
#include <climits>
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

static constexpr const char* TEST_USER       = "tap_passthrough_reuse_user";
static constexpr const char* TEST_BACKEND_PW = "p4ssth0ugh-r3us3-r34l!";
static constexpr const char* WRONG_PW        = "definitely-not-the-real-password";

/** @brief MySQL 8+ backend hostgroup in the TAP infra (mirrors e2e test). */
static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

/** @brief Run a query; diag on failure. */
static int do_query(MYSQL* mysql, const string& q) {
	if (mysql_query(mysql, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(mysql));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/** @brief Row count of stats_mysql_passthrough_auth_cache (-1 on error). */
static int cache_entry_count(MYSQL* admin) {
	if (mysql_query(admin, "SELECT COUNT(*) FROM stats_mysql_passthrough_auth_cache")) {
		diag("SELECT stats_mysql_passthrough_auth_cache failed: %s", mysql_error(admin));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	int n = (row && row[0]) ? atoi(row[0]) : -1;
	mysql_free_result(res);
	return n;
}

/** @brief Read a single counter from stats_mysql_passthrough_auth_metrics (-1 on error). */
static long long metric(MYSQL* admin, const char* name) {
	const string q =
		string("SELECT metric_value FROM stats_mysql_passthrough_auth_metrics "
		       "WHERE metric_name='") + name + "'";
	if (mysql_query(admin, q.c_str())) {
		diag("SELECT metric '%s' failed: %s", name, mysql_error(admin));
		return -1;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return -1;
	MYSQL_ROW row = mysql_fetch_row(res);
	long long v = (row && row[0]) ? atoll(row[0]) : -1;
	mysql_free_result(res);
	return v;
}

/** @brief Sum of ConnFree across servers in a hostgroup (0 if none/err). */
static int free_conns(MYSQL* admin, uint32_t hg) {
	const string q =
		string("SELECT IFNULL(SUM(ConnFree),0) FROM stats_mysql_connection_pool "
		       "WHERE hostgroup=") + std::to_string(hg);
	if (mysql_query(admin, q.c_str())) {
		diag("SELECT ConnFree failed: %s", mysql_error(admin));
		return 0;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return 0;
	MYSQL_ROW row = mysql_fetch_row(res);
	int n = (row && row[0]) ? atoi(row[0]) : 0;
	mysql_free_result(res);
	return n;
}

/**
 * @brief Connect through ProxySQL over TLS with the given credentials.
 *        Optionally run a trivial query first (to force a backend
 *        connection to be established and returned to the pool).
 * @return mysql_errno (0 on success).
 *
 * TLS is required: the caching_sha2_password full-auth exchange only
 * yields the cleartext to ProxySQL over a secured channel, and
 * mysql-passthrough_auth_require_tls defaults to 'true'. Same CLIENT_SSL
 * + mysql_ssl_set(all-NULL) pattern as test_passthrough_auth_e2e-t.
 */
static unsigned int try_connect(const CommandLine& cl, const char* user,
                                const char* pass, bool run_query) {
	MYSQL* m = mysql_init(NULL);
	if (!m) return UINT_MAX;
	mysql_options(m, MYSQL_DEFAULT_AUTH, "caching_sha2_password");
	mysql_ssl_set(m, NULL, NULL, NULL, NULL, NULL);
	const MYSQL* res = mysql_real_connect(
		m, cl.host, user, pass, NULL, cl.port, NULL, CLIENT_SSL);
	unsigned int err = res ? 0 : mysql_errno(m);
	if (!res) {
		diag("Frontend connect user='%s' pass='%s' failed: errno=%u msg='%s'",
			user, pass, err, mysql_error(m));
	} else if (run_query) {
		/* Establish an actual backend connection so a warm one is pooled. */
		if (mysql_query(m, "SELECT 1")) {
			diag("warm-up SELECT 1 failed: %s", mysql_error(m));
		} else {
			MYSQL_RES* r = mysql_store_result(m);
			if (r) mysql_free_result(r);
		}
	}
	mysql_close(m);
	return err;
}

int main() {
	CommandLine cl;

	/*
	 * Plan:
	 *   Setup (6): backend conn, admin conn, backend user, empty-pw row,
	 *              passthrough enabled, cache starts empty.
	 *   Body (11):
	 *     [warm]  (2) legit connect+query ok; cache populated (n=1)
	 *     [flush] (2) per-user cache flush ok; cache empty (n=0)
	 *     [pre]   (1) a warm backend connection is free in the pool
	 *     [ATTACK](1) wrong-pw connect DENIED (1045) -- force-new invariant
	 *     [corr]  (2) probes_failed_credentials +1; probes_ok unchanged
	 *     [corr]  (1) cache still empty after wrong-pw (n=0)
	 *     [ctrl]  (2) real-pw connect still succeeds; cache repopulated
	 *   Cleanup (2): DROP USER; mysql_users + variables restored.
	 *   Total: 6 + 11 + 2 = 19.
	 */
	plan(19);

	if (cl.getEnv()) {
		diag("CommandLine getEnv() failed");
		return exit_status();
	}

	/* -------- backend & admin connections -------- */
	MYSQL* backend = mysql_init(NULL);
	const MYSQL* bcr = mysql_real_connect(
		backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
		NULL, cl.mysql_port, NULL, 0);
	ok(bcr != NULL, "Connected to backend MySQL at %s:%d", cl.mysql_host, cl.mysql_port);
	if (!bcr) { mysql_close(backend); return exit_status(); }

	MYSQL* admin = mysql_init(NULL);
	const MYSQL* acr = mysql_real_connect(
		admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0);
	ok(acr != NULL, "Connected to ProxySQL admin at %s:%d", cl.admin_host, cl.admin_port);
	if (!acr) { mysql_close(backend); mysql_close(admin); return exit_status(); }

	/* -------- backend user with caching_sha2_password -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	const string create_user =
		string("CREATE USER '") + TEST_USER + "'@'%' "
		"IDENTIFIED WITH 'caching_sha2_password' BY '" + TEST_BACKEND_PW + "'";
	bool user_ok =
		(do_query(backend, create_user) == EXIT_SUCCESS) &&
		(do_query(backend, string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'") == EXIT_SUCCESS);
	ok(user_ok, "Backend user '%s' provisioned with caching_sha2_password", TEST_USER);

	/* -------- mysql_users empty-password row -------- */
	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	const string insert =
		string("INSERT INTO mysql_users (username, password, default_hostgroup, active) VALUES ('")
		+ TEST_USER + "', '', " + std::to_string(MYSQL8_HG) + ", 1)";
	bool row_ok =
		(do_query(admin, insert) == EXIT_SUCCESS) &&
		(do_query(admin, "LOAD MYSQL USERS TO RUNTIME") == EXIT_SUCCESS);
	ok(row_ok, "Empty-password row inserted for '%s' (default_hostgroup=%u)", TEST_USER, MYSQL8_HG);

	/* -------- enable pass-through (empty-password mode, TLS gate on) -------- */
	const vector<string> enable_queries {
		"SET mysql-passthrough_auth_enabled='true'",
		"SET mysql-passthrough_auth_require_tls='true'",
		"SET mysql-passthrough_auth_empty_password='true'",
		"SET mysql-passthrough_auth_unknown_users='false'",
		"SET mysql-default_authentication_plugin='caching_sha2_password'",
		/*
		 * Keep the per-user failure allowance comfortably above the single
		 * wrong-pw attempt this test makes, so the ATTACK step is denied by
		 * the credential check (1045), never masked by a rate-limit lockout.
		 */
		"SET mysql-passthrough_auth_max_failures_per_user='10'",
		"SET mysql-passthrough_auth_max_failures_per_ip='100'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};
	bool cfg_ok = true;
	for (const string& q : enable_queries) {
		if (do_query(admin, q) != EXIT_SUCCESS) { cfg_ok = false; break; }
	}
	ok(cfg_ok, "Pass-through enabled (empty-pw mode, TLS gate on, default_auth=caching_sha2)");

	/*
	 * The probe->backend leg needs TLS too (MySQL 8.4+ backends reject the
	 * plaintext caching_sha2_password full-auth). Mark the hostgroup's
	 * servers use_ssl=1, mirroring test_passthrough_auth_e2e-t.
	 */
	do_query(admin, string("UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* Start from a clean cache regardless of prior test state. */
	do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
	ok(cache_entry_count(admin) == 0, "Cache starts with zero entries");

	/* ============================================================
	 * [warm] Legitimate connect: probe succeeds, credential cached, and
	 *        a backend connection authed as U/REAL lands in the pool.
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW, /*run_query=*/true);
		ok(err == 0, "[warm] Legit connect with real password succeeds (errno=%u)", err);
		ok(cache_entry_count(admin) == 1, "[warm] Cache populated after legit connect");
	}

	/* ============================================================
	 * [flush] Clear ONLY the credential cache for U. The warm backend
	 *         connection stays in the pool -- this is the whole point.
	 * ============================================================ */
	{
		const string flush =
			string("PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER '") + TEST_USER + "'";
		ok(do_query(admin, flush) == EXIT_SUCCESS, "[flush] Per-user cache flush succeeds");
		ok(cache_entry_count(admin) == 0, "[flush] Credential cache empty after flush");
	}

	/* ============================================================
	 * [pre] Confirm the warm-pool window actually exists. If no backend
	 *       connection is free, the reuse hazard isn't being exercised;
	 *       we surface that explicitly rather than passing vacuously.
	 * ============================================================ */
	const int free_before = free_conns(admin, MYSQL8_HG);
	ok(free_before >= 1,
		"[pre] A warm backend connection is free in the pool (ConnFree=%d) -- reuse window is real",
		free_before);

	/* Baselines for the corroborating metric assertions. */
	const long long ok_before   = metric(admin, "probes_ok");
	const long long fail_before = metric(admin, "probes_failed_credentials");

	/* ============================================================
	 * [ATTACK] U + WRONG password, cache cold, warm U/REAL conn pooled.
	 *          MUST be denied (1045). errno 0 here == force-new regression
	 *          == silent auth bypass via pooled-connection reuse.
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, WRONG_PW, /*run_query=*/false);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[ATTACK] Wrong password DENIED despite warm pooled U/REAL conn "
			"(errno=%u, expected %u; errno 0 would mean pooled-conn reuse bypass)",
			err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/* ============================================================
	 * [corr] The denial came from a real backend probe rejection, not
	 *        from a short-circuit: the credential-failure counter must
	 *        advance and the success counter must NOT.
	 * ============================================================ */
	{
		const long long fail_after = metric(admin, "probes_failed_credentials");
		const long long ok_after   = metric(admin, "probes_ok");
		ok(fail_before >= 0 && fail_after == fail_before + 1,
			"[corr] probes_failed_credentials advanced by 1 (%lld -> %lld) -- backend actually rejected",
			fail_before, fail_after);
		ok(ok_before >= 0 && ok_after == ok_before,
			"[corr] probes_ok unchanged (%lld -> %lld) -- no false success recorded",
			ok_before, ok_after);
	}
	ok(cache_entry_count(admin) == 0, "[corr] Cache still empty after wrong-pw attempt");

	/* ============================================================
	 * [ctrl] Positive control: the real password still authenticates,
	 *        proving the ATTACK deny was password-specific, not a blanket
	 *        breakage of the pass-through path.
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW, /*run_query=*/false);
		ok(err == 0, "[ctrl] Real password still succeeds after the attack (errno=%u)", err);
		ok(cache_entry_count(admin) == 1, "[ctrl] Cache repopulated by the control connect");
	}

	/* -------- cleanup (run every step even on failure) -------- */
	do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
	{
		const int rc = do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
		ok(rc == EXIT_SUCCESS, "Cleanup: DROP USER on backend");
	}
	{
		int rc = EXIT_SUCCESS;
		rc |= do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
		rc |= do_query(admin, "LOAD MYSQL USERS TO RUNTIME");
		rc |= do_query(admin, "SET mysql-passthrough_auth_enabled='false'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_require_tls='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='3'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10'");
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: mysql_users + variables restored");
	}

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
