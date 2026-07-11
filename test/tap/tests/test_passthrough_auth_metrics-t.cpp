/**
 * @file test_passthrough_auth_metrics-t.cpp
 * @brief Verifies that the pass-through observability counters actually
 *        increment at the documented call sites (B7 follow-up).
 *
 * The metrics surface is @c stats_mysql_passthrough_auth_metrics with
 * rows (metric_name, metric_value) and the snake-case counter names
 * defined in @c MySQL_Passthrough_Auth_Cache::metrics_snapshot. Each
 * counter is monotonic-since-process-start; this test takes a
 * before/after delta around a single observable event and asserts the
 * delta is at least 1 (allowing concurrent test load from other
 * suites running on the same proxy to also bump counters, which would
 * only make the delta higher).
 *
 * Counters exercised (one per phase):
 *
 *   [1] probes_attempted + probes_ok                   -- successful probe
 *   [2] cache_hits                                     -- reconnect cache hit
 *   [3] probes_failed_credentials                      -- wrong-pw probe
 *
 * Counters NOT exercised by this test (each is covered elsewhere or
 * requires infrastructure this test deliberately avoids):
 *
 *   - inflight_cap_rejects: requires concurrent probes that exceed
 *     max_inflight_probes. A single-threaded TAP test that just sets
 *     max_inflight_probes=1 and runs a serial probe doesn't trigger
 *     the cap rejection -- the previous version of this test had a
 *     scenario [4] that asserted "counter is monotonic", which holds
 *     trivially even if bump_inflight_cap_rejects were deleted. We
 *     removed that scenario rather than ship a tautology.
 *   - lockouts_user / lockouts_ip: exercised by ratelimit-t.
 *   - cache_invalidations: exercised by invalidation-t.
 *
 * We assert deltas, not absolute values, so the test is robust to
 * other tests sharing the proxy bumping the same counters
 * concurrently.
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

static constexpr const char* TEST_USER       = "tap_pt_metrics_user";
static constexpr const char* TEST_BACKEND_PW = "metr1cs-3nd-2-3nd!";
static constexpr const char* WRONG_PW        = "definitely-not-the-real-password";

static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static int do_query(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Read a single metric by name from
 *        @c stats_mysql_passthrough_auth_metrics.
 *
 * Returns -1 if the row is missing or the query failed -- treat as
 * "no signal" rather than 0 to make test failures less misleading.
 */
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

static unsigned int try_connect(
	const CommandLine& cl, const char* user, const char* pass
) {
	MYSQL* m = mysql_init(NULL);
	if (!m) return UINT_MAX;
	mysql_options(m, MYSQL_DEFAULT_AUTH, "caching_sha2_password");
	/*
	 * CLIENT_SSL is required on the frontend leg for caching_sha2_password
	 * full-auth. ProxySQL's PPHR_passthrough_init only handles the
	 * cleartext-over-TLS branch. See e2e-t for the full protocol
	 * rationale.
	 */
	mysql_ssl_set(m, NULL, NULL, NULL, NULL, NULL);
	const MYSQL* res = mysql_real_connect(
		m, cl.host, user, pass, NULL, cl.port, NULL, CLIENT_SSL
	);
	const unsigned int err = res ? 0 : mysql_errno(m);
	mysql_close(m);
	return err;
}

int main() {
	CommandLine cl;

	/*
	 * Plan: 4 setup + 3 deltas + 2 cleanup = 9.
	 *
	 *   Setup (4):
	 *     backend connect, admin connect, user provisioned,
	 *     passthrough enabled
	 *
	 *   [1] probes_attempted++ and probes_ok++ on first probe
	 *   [2] cache_hits++ on reconnect (and probes_attempted UNCHANGED)
	 *   [3] probes_failed_credentials++ on wrong pw
	 *
	 *   Cleanup (2): DROP USER, restore globals
	 */
	plan(9);

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

	/* -------- backend user + empty-pw row -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	const bool user_ok =
		(do_query(backend,
			string("CREATE USER '") + TEST_USER + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + TEST_BACKEND_PW + "'") == EXIT_SUCCESS) &&
		(do_query(backend,
			string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'") == EXIT_SUCCESS);
	ok(user_ok, "Backend user '%s' provisioned", TEST_USER);

	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	do_query(admin,
		string("INSERT INTO mysql_users (username, password, default_hostgroup, active) VALUES ('")
		+ TEST_USER + "', '', " + std::to_string(MYSQL8_HG) + ", 1)");
	do_query(admin, "LOAD MYSQL USERS TO RUNTIME");

	bool cfg_ok = true;
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_enabled='true'") == EXIT_SUCCESS);
	/* require_tls left at default 'true'; client connects with CLIENT_SSL. See e2e-t for rationale. */
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_require_tls='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_empty_password='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_unknown_users='false'") == EXIT_SUCCESS);
	/*
	 * Raise failure caps very high for the duration of this test
	 * (cleanup restores defaults). mysql84-g4 also runs ratelimit-t,
	 * security-t, and unknown_user-t, each of which can drive failed
	 * probes from the same client IP. On default caps (3/user, 10/IP)
	 * any cross-test pollution of the per-IP deque would lock us out
	 * before scenario [3] (wrong-pw) gets to bump
	 * probes_failed_credentials, turning the assertion into a
	 * spurious lockout error. Caps at 10000 make that impossible.
	 * Mirrors the pattern in invalidation-t / security-t /
	 * unknown_user-t.
	 */
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='10000'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10000'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-default_authentication_plugin='caching_sha2_password'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == EXIT_SUCCESS);
	ok(cfg_ok, "Pass-through configured with tight lockout bypassed (caps set high)");

	/*
	 * Ensure the target hostgroup has use_ssl=1 so the passthrough probe
	 * negotiates TLS to the backend.
	 *
	 * The pass-through probe path (handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT)
	 * only enables TLS for the backend leg if the selected MySrvC has use_ssl set:
	 *
	 *     if (mysrvc->use_ssl && mysrvc->port) {
	 *         probe_ssl_params = MyHGM->get_Server_SSL_Params(...);
	 *         MySQL_Connection::set_ssl_params(probe, probe_ssl_params);
	 *     }
	 *     MYSQL *result = mysql_real_connect(probe, ...);
	 *
	 * The dbdeployer-mysql84 (and mysql90/mysql95) infras used by the
	 * mysql84-g4 group (via TAP_MYSQL8_BACKEND_HG) seed mysql_servers rows
	 * without use_ssl=1. Without this UPDATE+LOAD, every probe is plaintext.
	 * MySQL 8.4+ backends (and the caching_sha2_password full-auth exchange
	 * that the probe relies on) typically fail or reject in that case, so
	 * "success" scenarios see errno != 0 and the TAP assertions fail.
	 *
	 * We do this once, right after the test's passthrough configuration
	 * block and before the first probe, so the setting is live for the
	 * entire test (including the observability counter scenarios).
	 */
	do_query(admin,
		string("UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* ============================================================
	 * Scenario 1: successful probe bumps probes_attempted and
	 *             probes_ok.
	 * ============================================================ */
	{
		const int64_t pa_before = read_metric(admin, "probes_attempted");
		const int64_t po_before = read_metric(admin, "probes_ok");

		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		(void)err;

		const int64_t pa_after = read_metric(admin, "probes_attempted");
		const int64_t po_after = read_metric(admin, "probes_ok");

		ok(pa_before >= 0 && pa_after >= pa_before + 1
			&& po_before >= 0 && po_after >= po_before + 1,
			"[1] probes_attempted and probes_ok each incremented "
			"(attempted: %lld -> %lld, ok: %lld -> %lld)",
			(long long)pa_before, (long long)pa_after,
			(long long)po_before, (long long)po_after);
	}

	/* ============================================================
	 * Scenario 2: reconnect uses the cache, bumps cache_hits.
	 *             probes_attempted should NOT advance on this path
	 *             (cache hit short-circuits before the probe).
	 * ============================================================ */
	{
		const int64_t ch_before = read_metric(admin, "cache_hits");
		const int64_t pa_before = read_metric(admin, "probes_attempted");

		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		(void)err;

		const int64_t ch_after = read_metric(admin, "cache_hits");
		const int64_t pa_after = read_metric(admin, "probes_attempted");

		ok(ch_after >= ch_before + 1 && pa_after == pa_before,
			"[2] cache_hits++ (%lld -> %lld) AND probes_attempted "
			"unchanged (%lld -> %lld, expected equal)",
			(long long)ch_before, (long long)ch_after,
			(long long)pa_before, (long long)pa_after);
	}

	/* ============================================================
	 * Scenario 3: wrong password bumps probes_failed_credentials.
	 *             Flush cache first so we definitely go through the
	 *             probe path (cache hit would skip credential check).
	 * ============================================================ */
	{
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		const int64_t pfc_before = read_metric(admin, "probes_failed_credentials");

		const unsigned int err = try_connect(cl, TEST_USER, WRONG_PW);
		(void)err;

		const int64_t pfc_after = read_metric(admin, "probes_failed_credentials");
		ok(pfc_after >= pfc_before + 1,
			"[3] probes_failed_credentials++ on wrong-pw "
			"(%lld -> %lld)",
			(long long)pfc_before, (long long)pfc_after);
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
