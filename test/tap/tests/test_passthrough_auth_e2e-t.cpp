/**
 * @file test_passthrough_auth_e2e-t.cpp
 * @brief End-to-end test for pass-through authentication.
 *
 * Drives an actual probe through the caching_sha2_password full-auth
 * exchange: configures a backend user with caching_sha2_password as
 * their auth plugin, configures ProxySQL with an empty-password row in
 * mysql_users for the same username, then verifies that a client
 * connecting through ProxySQL with the real password succeeds and that
 * the credential is then cached for the next connect.
 *
 * Requires a backend MySQL 8+ instance reachable at @c cl.mysql_host /
 * @c cl.mysql_port -- caching_sha2_password is the default in 8.0+ and
 * not supported on legacy servers. Registered in groups.json under the
 * mysql84+ / mysql9x / mysql95 groups for that reason.
 *
 * Scenarios exercised in order:
 *   1. Empty-password row pass-through: first connect probes & caches
 *      (cache went from 0 entries to 1).
 *   2. Reconnect within the same test: cache-hit fast path (no probe;
 *      stats table still shows the same entry).
 *   3. PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER '<user>' clears
 *      the specific entry without touching others (since there's only
 *      one entry, the table goes empty).
 *   4. Reconnect after flush: probes the backend again, re-populates.
 *   5. Connect with the WRONG password: expect access denied AND the
 *      cache entry NOT replaced (the rate-limit failure path doesn't
 *      poison the cache).
 *   6. Connect with mysql_native_password against the same empty-pw
 *      row: expect access denied (spec §3.2 behavior change).
 *   7. PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE (no arg): empty cache.
 *
 * Spec reference: doc/internal/passthrough_authentication.md
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
 * @brief Test fixture constants.
 *
 * The username/password pair is created on the backend by this test and
 * dropped at the end; pick names unlikely to collide with anything that
 * might already be on the test backend.
 */
static constexpr const char* TEST_USER       = "tap_passthrough_e2e_user";
static constexpr const char* TEST_BACKEND_PW = "p4ssth0ugh-3nd-2-3nd!";
static constexpr const char* WRONG_PW        = "definitely-not-the-real-password";

/**
 * @brief Default hostgroup for MySQL 8+ backends in the TAP infra.
 *
 * Overridable via TAP_MYSQL8_BACKEND_HG (used identically by
 * reg_test_4935-caching_sha2-t.cpp). The infra setup leaves a healthy
 * mysql 8 backend in this hostgroup.
 */
static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

/**
 * @brief Execute a query and diag the error if it fails.
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on query error.
 */
static int do_query(MYSQL* mysql, const string& q) {
	if (mysql_query(mysql, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(mysql));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Count rows in stats_mysql_passthrough_auth_cache.
 *
 * Returns -1 on query failure, otherwise the row count. The caller is
 * the admin connection.
 */
static int cache_entry_count(MYSQL* admin) {
	if (mysql_query(admin, "SELECT COUNT(*) FROM stats_mysql_passthrough_auth_cache")) {
		diag("SELECT FROM stats_mysql_passthrough_auth_cache failed: %s", mysql_error(admin));
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
 * @brief Look up the learned_at_us value for a specific user in the cache.
 *
 * Used to confirm whether a connect that "should" cache-hit actually did
 * (entry's learned_at must NOT change) vs re-probed (learned_at advances).
 * Returns "" (empty) when no entry is present.
 */
static string cache_learned_at(MYSQL* admin, const string& user) {
	const string q =
		"SELECT learned_at FROM stats_mysql_passthrough_auth_cache WHERE username='" + user + "'";
	if (mysql_query(admin, q.c_str())) return {};
	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) return {};
	MYSQL_ROW row = mysql_fetch_row(res);
	string out;
	if (row && row[0]) out = row[0];
	mysql_free_result(res);
	return out;
}

/**
 * @brief Attempt a frontend connect through ProxySQL with the given
 *        credentials and auth plugin.
 *
 * @param cl              CommandLine fixture (provides host/port).
 * @param user            Frontend username.
 * @param pass            Cleartext password to send.
 * @param req_auth_plugin Either "caching_sha2_password" (default) or
 *                        "mysql_native_password" to test the §3.2 cross-
 *                        plugin rejection.
 * @return The mysql_errno (or 0 on success). Caller decides what is
 *         "expected" -- 0 for success, 1045 for access denied, etc.
 *         The diag includes the human-readable mysql_error for triage.
 */
static unsigned int try_connect(
	const CommandLine& cl, const char* user, const char* pass,
	const char* req_auth_plugin = "caching_sha2_password"
) {
	MYSQL* m = mysql_init(NULL);
	if (!m) return UINT_MAX;
	mysql_options(m, MYSQL_DEFAULT_AUTH, req_auth_plugin);
	if (string(req_auth_plugin) == "mysql_clear_password") {
		bool enable_cleartext = true;
		mysql_options(m, MYSQL_ENABLE_CLEARTEXT_PLUGIN, &enable_cleartext);
	}
	/*
	 * TLS is REQUIRED on the frontend leg for the caching_sha2_password
	 * full-auth exchange to complete. After ProxySQL replies with the
	 * AuthMoreData{0x04} ("perform_full_authentication") byte, the client
	 * must send its cleartext password. Per the caching_sha2_password
	 * protocol, this cleartext can flow over the wire in one of two
	 * forms:
	 *   1. Plaintext over a TLS-secured channel (what we do here).
	 *   2. RSA-encrypted under the server's public key, fetched via
	 *      the "request public key" subcommand (0x02). ProxySQL's
	 *      pass-through dispatch (PPHR_passthrough_init in
	 *      lib/MySQL_Protocol.cpp) does NOT implement this branch --
	 *      it only handles stages 0 (send 0x04) and 5 (cleartext
	 *      received), so a non-TLS client with no pre-cached entry
	 *      disconnects with errno 2061 ("Couldn't read RSA public key
	 *      from server").
	 *
	 * The mysql_ssl_set call with all-NULL CA/cert paths leaves
	 * verification disabled -- we trust the local test infra cert
	 * chain. CLIENT_SSL in the connect flags triggers the TLS upgrade
	 * during the handshake. Pattern mirrors test_auth_methods-t.cpp
	 * and reg_test_4935-caching_sha2-t.cpp.
	 */
	mysql_ssl_set(m, NULL, NULL, NULL, NULL, NULL);
	const MYSQL* res = mysql_real_connect(
		m, cl.host, user, pass, NULL, cl.port, NULL, CLIENT_SSL
	);
	const unsigned int err = res ? 0 : mysql_errno(m);
	if (!res) {
		diag("Frontend connect for user='%s' pass='%s' plugin='%s' failed: errno=%u msg='%s'",
			user, pass, req_auth_plugin, err, mysql_error(m));
	}
	mysql_close(m);
	return err;
}

int main() {
	CommandLine cl;

	/*
	 * Test plan -- the count is the total number of ok() calls below.
	 *
	 *   Setup (7):
	 *     1  backend connect succeeded
	 *     1  admin connect succeeded
	 *     1  backend user created with caching_sha2_password
	 *     1  mysql_users empty-pw row inserted + loaded to runtime
	 *     1  passthrough variables set (one combined ok)
	 *     1  passthrough_auth_empty_password observed at "true"
	 *     1  cache empty at the start
	 *
	 *   Scenarios (13):
	 *     [1] (2) connect ok, cache populated (n=1)
	 *     [2] (2) reconnect ok, learned_at unchanged (cache hit)
	 *     [3] (2) FOR USER flush ok, cache empty
	 *     [4] (2) re-probe after flush ok, cache populated (n=1)
	 *     [5] (2) wrong pw rejected, cache unchanged
	 *     [6] (1) mysql_native_password against empty-pw row rejected
	 *     [7] (2) no-arg flush ok, cache empty
	 *
	 *   Cleanup (2):
	 *     1  DROP USER on backend
	 *     1  mysql_users + variables restored
	 *
	 *   Total: 7 + 13 + 2 = 22.
	 */
	plan(22);

	if (cl.getEnv()) {
		diag("CommandLine getEnv() failed");
		return exit_status();
	}

	/* -------- backend & admin connections -------- */
	MYSQL* backend = mysql_init(NULL);
	const MYSQL* bcr = mysql_real_connect(
		backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
		NULL, cl.mysql_port, NULL, 0
	);
	ok(bcr != NULL, "Connected to backend MySQL at %s:%d", cl.mysql_host, cl.mysql_port);
	if (!bcr) {
		mysql_close(backend);
		return exit_status();
	}

	MYSQL* admin = mysql_init(NULL);
	const MYSQL* acr = mysql_real_connect(
		admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0
	);
	ok(acr != NULL, "Connected to ProxySQL admin at %s:%d", cl.admin_host, cl.admin_port);
	if (!acr) {
		mysql_close(backend);
		mysql_close(admin);
		return exit_status();
	}

	/* -------- backend user with caching_sha2_password -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	const string create_user =
		string("CREATE USER '") + TEST_USER + "'@'%' "
		"IDENTIFIED WITH 'caching_sha2_password' BY '" + TEST_BACKEND_PW + "'";
	const string grant =
		string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'";
	bool user_ok =
		(do_query(backend, create_user) == EXIT_SUCCESS) &&
		(do_query(backend, grant) == EXIT_SUCCESS);
	ok(user_ok, "Backend user '%s' provisioned with caching_sha2_password", TEST_USER);

	/* -------- mysql_users row with empty password -------- */
	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	const string insert =
		string("INSERT INTO mysql_users (username, password, default_hostgroup, active) VALUES ('")
		+ TEST_USER + "', '', " + std::to_string(MYSQL8_HG) + ", 1)";
	bool row_ok =
		(do_query(admin, insert) == EXIT_SUCCESS) &&
		(do_query(admin, "LOAD MYSQL USERS TO RUNTIME") == EXIT_SUCCESS);
	ok(row_ok, "Empty-password row inserted for '%s' (default_hostgroup=%u)", TEST_USER, MYSQL8_HG);

	/* -------- enable pass-through -------- */
	const vector<string> enable_queries {
		"SET mysql-passthrough_auth_enabled='true'",
		/*
		 * Leave mysql-passthrough_auth_require_tls at its default ('true').
		 * The test's try_connect() now wires CLIENT_SSL on every probe (see
		 * the comment block in that helper), so the frontend leg is
		 * TLS-protected and the gate is satisfied. Setting require_tls='true'
		 * explicitly here doubles as a regression check: a future code
		 * change that breaks the TLS plumbing would surface as a failed
		 * probe at scenario [1] rather than silently bypassing the gate.
		 */
		"SET mysql-passthrough_auth_require_tls='true'",
		"SET mysql-passthrough_auth_empty_password='true'",
		/*
		 * Ensure the unknown_users path stays off so this test only
		 * exercises the empty-password row case. The two paths share the
		 * same dispatch but synthesize different defaults; we cover the
		 * empty-pw side here.
		 */
		"SET mysql-passthrough_auth_unknown_users='false'",
		/*
		 * Default authentication plugin must announce caching_sha2_password
		 * so the client driver picks up the full-auth exchange. This is
		 * the spec's primary mode for Phase 1.
		 */
		"SET mysql-default_authentication_plugin='caching_sha2_password'",
		"LOAD MYSQL VARIABLES TO RUNTIME",
	};
	bool cfg_ok = true;
	for (const string& q : enable_queries) {
		if (do_query(admin, q) != EXIT_SUCCESS) { cfg_ok = false; break; }
	}
	ok(cfg_ok, "Pass-through enabled, TLS gate on (client connects with CLIENT_SSL), default_auth=caching_sha2_password");

	/*
	 * Ensure the target hostgroup's servers are marked use_ssl=1 so the
	 * passthrough backend probe (mysql_real_connect inside
	 * handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT) will
	 * establish a TLS connection to the backend.
	 *
	 * The probe path is:
	 *   handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
	 *     ...
	 *     if (mysrvc->use_ssl && mysrvc->port) {
	 *         probe_ssl_params = MyHGM->get_Server_SSL_Params(...);
	 *         MySQL_Connection::set_ssl_params(probe, probe_ssl_params);
	 *         ...
	 *     }
	 *     MYSQL *result = mysql_real_connect(probe, mysrvc->address, ...);
	 *
	 * If MySrvC->use_ssl is false, the probe is plaintext. The mysql84+
	 * (and mysql90+/mysql95+) dbdeployer infras used by the mysql84-g4
	 * group (see test/infra/infra-dbdeployer-mysql84/.env exporting
	 * TAP_MYSQL8_BACKEND_HG=${WHG}, and the post hook in
	 * test/infra/infra-dbdeployer-mysql84/bin/docker-proxy-post.bash)
	 * seed mysql_servers rows without use_ssl=1.
	 *
	 * Without this UPDATE+LOAD, every probe in this test is plaintext.
	 * MySQL 8.4+ backends commonly reject plaintext connections or the
	 * caching_sha2_password full-auth exchange fails, so all success
	 * scenarios (first connect, reconnect, re-probe after flush) see
	 * errno != 0 instead of 0, and the TAP plan fails.
	 *
	 * We do the UPDATE+LOAD right after the test's passthrough
	 * configuration block and before the first try_connect, so it is
	 * live for the entire test. This only affects the probe->backend
	 * leg; the frontend TLS requirement (spec §7.1) is enforced by
	 * CLIENT_SSL + mysql_ssl_set in try_connect().
	 */
	do_query(admin,
		string("UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* -------- verify gate state -------- */
	{
		const int set_ok = mysql_query(admin,
			"SELECT variable_value FROM global_variables "
			"WHERE variable_name='mysql-passthrough_auth_empty_password'");
		string val;
		if (set_ok == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
			if (row && row[0]) val = row[0];
			if (res) mysql_free_result(res);
		}
		ok(val == "true", "passthrough_auth_empty_password=true (got '%s')", val.c_str());
	}

	/* -------- cache starts empty -------- */
	ok(cache_entry_count(admin) == 0, "Cache starts with zero entries");

	/* ============================================================
	 * Scenario 1 -- first connect drives a probe and caches the credential
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0, "[1] First connect with real password succeeds (errno=%u)", err);
		const int n = cache_entry_count(admin);
		ok(n == 1, "[1] Cache populated after first connect (n=%d)", n);
	}

	const string learned_at_1 = cache_learned_at(admin, TEST_USER);

	/* ============================================================
	 * Scenario 2 -- reconnect hits the cache (no new probe)
	 * The proof: learned_at_us is monotonic_time at insert time, so a
	 * cache-hit path does NOT overwrite the entry and learned_at stays
	 * identical across the second connect.
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0, "[2] Reconnect with real password succeeds (errno=%u)", err);
		const string learned_at_2 = cache_learned_at(admin, TEST_USER);
		ok(!learned_at_1.empty() && learned_at_1 == learned_at_2,
			"[2] Cache hit on reconnect (learned_at unchanged: '%s' == '%s')",
			learned_at_1.c_str(), learned_at_2.c_str());
	}

	/* ============================================================
	 * Scenario 3 -- PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER
	 * removes the specific entry.
	 * ============================================================ */
	{
		const string flush =
			string("PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE FOR USER '") + TEST_USER + "'";
		const bool flush_ok = (do_query(admin, flush) == EXIT_SUCCESS);
		ok(flush_ok, "[3] FLUSH ... FOR USER '%s' succeeds", TEST_USER);
		const int n = cache_entry_count(admin);
		ok(n == 0, "[3] Cache empty after per-user flush (n=%d)", n);
	}

	/* ============================================================
	 * Scenario 4 -- after flush, next connect re-probes
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0, "[4] Re-probe after flush succeeds (errno=%u)", err);
		const int n = cache_entry_count(admin);
		ok(n == 1, "[4] Cache re-populated after re-probe (n=%d)", n);
	}

	const string learned_at_after_reprobe = cache_learned_at(admin, TEST_USER);

	/* ============================================================
	 * Scenario 5 -- wrong password rejected, cache unchanged
	 * The probe must fail against the backend (ER 1045) and the cache
	 * entry from the previous successful probe must NOT be overwritten
	 * with the bad password.
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, WRONG_PW);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[5] Wrong password rejected (errno=%u, expected %u)",
			err, (unsigned)ER_ACCESS_DENIED_ERROR);
		const string learned_at_after_wrong = cache_learned_at(admin, TEST_USER);
		ok(!learned_at_after_reprobe.empty() &&
			learned_at_after_reprobe == learned_at_after_wrong,
			"[5] Cache entry unchanged after wrong-pw probe ('%s' == '%s')",
			learned_at_after_reprobe.c_str(), learned_at_after_wrong.c_str());
	}

	/* ============================================================
	 * Scenario 6 -- mysql_native_password against empty-pw row rejected
	 * (spec §3.2 -- empty-pw row no longer permits passwordless login,
	 * AND non-caching_sha2 plugins can't drive pass-through). This is
	 * commit f80a5f9's fix.
	 *
	 * The mariadb client falls back to mysql_native_password for the
	 * passwordless case when MYSQL_DEFAULT_AUTH is set to it. Even with
	 * the real backend password, this MUST be rejected because the
	 * dispatch only accepts caching_sha2_password.
	 * ============================================================ */
	{
		const unsigned int err = try_connect(
			cl, TEST_USER, TEST_BACKEND_PW, "mysql_native_password");
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[6] mysql_native_password against empty-pw row rejected "
			"(errno=%u, expected %u)",
			err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/* ============================================================
	 * Scenario 7 -- no-arg flush clears the cache completely
	 * ============================================================ */
	{
		const bool flush_ok =
			(do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE") == EXIT_SUCCESS);
		ok(flush_ok, "[7] FLUSH PASSTHROUGH_AUTH_CACHE (no-arg) succeeds");
		const int n = cache_entry_count(admin);
		ok(n == 0, "[7] Cache empty after global flush (n=%d)", n);
	}

	/*
	 * Cleanup: ALL queries must run even if one fails -- a partial cleanup
	 * leaves the next test (sharing the same ProxySQL + backend infra) in
	 * an undefined state. Use bitwise OR so the bool aggregates without
	 * short-circuiting; success = every query returned EXIT_SUCCESS.
	 */
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
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: mysql_users + variables restored");
	}

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
