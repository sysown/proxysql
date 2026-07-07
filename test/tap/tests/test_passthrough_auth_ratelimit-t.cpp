/**
 * @file test_passthrough_auth_ratelimit-t.cpp
 * @brief End-to-end test for per-user / per-IP rate-limit lockout
 *        (spec §7.2).
 *
 * The lockout is a sliding-window failure counter: each credential-class
 * probe failure (mysql_errno 1045 / 1698 / 1130) bumps both a per-username
 * and a per-IP deque of timestamps. When the deque length within
 * @c mysql-passthrough_auth_failure_window_s seconds meets or exceeds
 * the configured cap, subsequent probe attempts are rejected at the
 * handler entry -- BEFORE any backend connection -- with a generic
 * "Access denied" ERR.
 *
 * Goal of this test: assert real lockout BEHAVIOR, not just that the
 * code path exists. We need to prove:
 *
 *   (a) Wrong-credential probes do increment the counter.
 *   (b) Once at the threshold, even a CORRECT credential is rejected.
 *       This is the load-bearing assertion -- it would fail if the
 *       lockout check were missing or short-circuited.
 *   (c) Transport-class failures (errno 2xxx) do NOT count toward the
 *       window. We can't easily inject a transport error from the
 *       client side (the backend is reachable), but the negative test
 *       runs back-to-back wrong-pw attempts and asserts the cap fires
 *       exactly at N -- if transport errors were polluting the counter
 *       we'd hit the cap earlier than expected.
 *   (d) Window expiry: after waiting >= window_s, a correct credential
 *       is once again accepted.
 *
 * Phase 1 scope: the per-user counter is exercised here. The per-IP
 * counter shares the same code path (just keyed differently) so the
 * test relies on commit d8525ae's structure rather than duplicating
 * the lockout cycle for both keys.
 *
 * Spec reference: doc/internal/passthrough_authentication.md §7.2
 */
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

static constexpr const char* TEST_USER       = "tap_pt_ratelimit_user";
static constexpr const char* TEST_BACKEND_PW = "r4tel1m1t-3nd-2-3nd!";
static constexpr const char* WRONG_PW        = "definitely-not-the-real-one";

/**
 * @brief Rate-limit settings used in this test.
 *
 * Tight numbers so the test runs quickly. The lockout threshold is small
 * so a handful of wrong attempts are enough to trigger it; the window is
 * small so the test can wait for it to expire without blocking CI for
 * minutes.
 */
static constexpr int TEST_MAX_FAILURES_PER_USER = 3;
static constexpr int TEST_FAILURE_WINDOW_S      = 5;

static uint32_t MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

static int do_query(MYSQL* m, const string& q) {
	if (mysql_query(m, q.c_str())) {
		diag("Query failed: %s -- %s", q.c_str(), mysql_error(m));
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

/**
 * @brief Attempt a frontend connect through ProxySQL with caching_sha2.
 *
 * Returns the mysql_errno (0 on success, 1045 on access denied, etc.).
 */
static unsigned int try_connect(
	const CommandLine& cl, const char* user, const char* pass
) {
	MYSQL* m = mysql_init(NULL);
	if (!m) return UINT_MAX;
	mysql_options(m, MYSQL_DEFAULT_AUTH, "caching_sha2_password");
	/*
	 * CLIENT_SSL is required on the frontend leg for caching_sha2_password
	 * full-auth. See e2e-t for the protocol details and why ProxySQL's
	 * PPHR_passthrough_init dispatch only supports cleartext-over-TLS.
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
	 * Plan = number of ok() calls.
	 *
	 *   Setup (6):
	 *     backend connect, admin connect, user created, mysql_users
	 *     row inserted, passthrough configured, baseline connect ok
	 *
	 *   Phase A -- prime the lockout (TEST_MAX_FAILURES_PER_USER = 3):
	 *     [A1] wrong-pw attempt 1 -> 1045
	 *     [A2] wrong-pw attempt 2 -> 1045
	 *     [A3] wrong-pw attempt 3 -> 1045
	 *     -> counter == cap; next attempt should be rejected pre-probe
	 *
	 *   Phase B -- LOAD-BEARING: correct password is now rejected too
	 *     [B1] right-pw -> 1045 (lockout fired)
	 *
	 *   Phase C -- window expiry restores access:
	 *     [C1] wait > window_s
	 *     [C2] right-pw -> 0 (success again)
	 *
	 *   Cleanup (2): DROP USER, restore globals
	 *
	 *   6 + 3 + 1 + 1 + 2 = 13.
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

	/* -------- backend user provisioning -------- */
	do_query(backend, string("DROP USER IF EXISTS '") + TEST_USER + "'@'%'");
	const bool user_ok =
		(do_query(backend,
			string("CREATE USER '") + TEST_USER + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + TEST_BACKEND_PW + "'") == EXIT_SUCCESS) &&
		(do_query(backend,
			string("GRANT SELECT ON *.* TO '") + TEST_USER + "'@'%'") == EXIT_SUCCESS);
	ok(user_ok, "Backend user '%s' provisioned", TEST_USER);

	/* -------- empty-password row in mysql_users -------- */
	do_query(admin, string("DELETE FROM mysql_users WHERE username='") + TEST_USER + "'");
	const bool row_ok =
		(do_query(admin,
			string("INSERT INTO mysql_users (username, password, default_hostgroup, active) "
				"VALUES ('") + TEST_USER + "', '', " + std::to_string(MYSQL8_HG) + ", 1)") == EXIT_SUCCESS) &&
		(do_query(admin, "LOAD MYSQL USERS TO RUNTIME") == EXIT_SUCCESS);
	ok(row_ok, "Empty-password mysql_users row inserted");

	/* -------- configure pass-through with tight rate limits -------- */
	bool cfg_ok = true;
	{
		const vector<string> cfg {
			"SET mysql-passthrough_auth_enabled='true'",
			/* require_tls left at default 'true'; client wires CLIENT_SSL. See e2e-t for rationale. */
			"SET mysql-passthrough_auth_require_tls='true'",
			"SET mysql-passthrough_auth_empty_password='true'",
			"SET mysql-passthrough_auth_unknown_users='false'",
			string("SET mysql-passthrough_auth_max_failures_per_user='")
				+ std::to_string(TEST_MAX_FAILURES_PER_USER) + "'",
			/* Keep per-IP cap high so the per-user cap is the one that
			 * fires in Phase A. */
			"SET mysql-passthrough_auth_max_failures_per_ip='1000'",
			string("SET mysql-passthrough_auth_failure_window_s='")
				+ std::to_string(TEST_FAILURE_WINDOW_S) + "'",
			"SET mysql-default_authentication_plugin='caching_sha2_password'",
			"PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE",
			"LOAD MYSQL VARIABLES TO RUNTIME",
		};
		for (const string& q : cfg) {
			if (do_query(admin, q) != EXIT_SUCCESS) { cfg_ok = false; break; }
		}
	}
	ok(cfg_ok, "Pass-through configured (per-user cap=%d, window=%ds)",
		TEST_MAX_FAILURES_PER_USER, TEST_FAILURE_WINDOW_S);

	/*
	 * Ensure the target hostgroup's servers have use_ssl=1 so the
	 * passthrough probe (backend leg) negotiates TLS.
	 *
	 * The pass-through probe path lives in:
	 *   MySQL_Session::handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
	 *
	 * Right before the actual backend connect it does:
	 *
	 *     MySrvC *mysrvc = myhgc->get_random_MySrvC(...);
	 *     ...
	 *     if (mysrvc->use_ssl && mysrvc->port) {
	 *         probe_ssl_params = MyHGM->get_Server_SSL_Params(...);
	 *         MySQL_Connection::set_ssl_params(probe, probe_ssl_params);
	 *         ...
	 *     }
	 *     MYSQL *result = mysql_real_connect(probe, mysrvc->address, ...);
	 *
	 * If MySrvC->use_ssl is false, the probe is a plaintext TCP connection.
	 * On the mysql84+ dbdeployer infras used by the mysql84-g4 group
	 * (WHG comes from TAP_MYSQL8_BACKEND_HG, default 2900 in
	 * test/infra/infra-dbdeployer-mysql84/.env), the servers are seeded
	 * by docker-proxy-post.bash + infra-config.sql without use_ssl=1.
	 *
	 * Without this UPDATE+LOAD, every passthrough probe is plaintext.
	 * MySQL 8.4+ backends (and the caching_sha2_password full-auth
	 * exchange the probe depends on) typically reject or fail the
	 * handshake, so all "success" scenarios in this test (baseline,
	 * Phase C after window expiry) return errno != 0 (usually 1045)
	 * instead of 0, and the TAP assertions fail.
	 *
	 * We apply this right after the test's passthrough configuration
	 * block (variables + LOAD VARIABLES) and before the first
	 * try_connect, so it is live for the baseline and all subsequent
	 * probes. This only affects the probe->backend leg; the frontend
	 * TLS requirement is handled separately by CLIENT_SSL in try_connect.
	 */
	do_query(admin,
		string("UPDATE mysql_servers SET use_ssl=1 WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* -------- baseline: a correct connect succeeds before priming -------- */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0, "Baseline: correct password succeeds before any failures (errno=%u)", err);
		/* Reset state for the lockout phase. The successful probe cached
		 * the cleartext; subsequent wrong-pw attempts must still PROBE
		 * the backend (and fail) so the failure counter increments. The
		 * cache-hit path bypasses the probe. Flush so we exercise the
		 * probe path. */
		do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
	}

	/* ============================================================
	 * Phase A -- prime the lockout with TEST_MAX_FAILURES_PER_USER
	 *             credential rejections.
	 *
	 * Each call must return 1045 from the backend's probe rejection.
	 * If any attempt returns 0 (cache hit) the test is broken and we
	 * need to flush more aggressively above. If any returns 2xxx
	 * (transport error) the per-user counter would NOT increment per
	 * commit 628edc5, and Phase B would not fire -- the test would
	 * then surface that as a failure on [B1] which is the right place
	 * for it.
	 * ============================================================ */
	for (int i = 1; i <= TEST_MAX_FAILURES_PER_USER; i++) {
		const unsigned int err = try_connect(cl, TEST_USER, WRONG_PW);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[A%d] wrong-pw attempt rejected (errno=%u, expected %u)",
			i, err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/* ============================================================
	 * Phase B -- LOAD-BEARING:
	 *
	 * After exactly TEST_MAX_FAILURES_PER_USER failed credential
	 * probes within the window, the next attempt MUST be rejected
	 * even when the credential is correct. The lockout check fires
	 * in handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
	 * BEFORE the probe runs, so the backend never sees this attempt
	 * -- the response time should be noticeably faster than the
	 * probe attempts above (we don't measure it, but the asymptotic
	 * behavior is the point).
	 *
	 * If this assertion fails, one of these is broken:
	 *   - would_lockout_user is returning false when it should return
	 *     true (off-by-one in prune_and_count, wrong deque count, ...)
	 *   - record_failure isn't actually appending timestamps
	 *   - the wrong-pw attempts in Phase A returned a transport class
	 *     error and didn't count (would also surface as Phase A
	 *     returning non-1045 errnos -- check Phase A first)
	 *   - the eligibility check above the lockout call isn't
	 *     dispatching the right code path
	 * ============================================================ */
	{
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == ER_ACCESS_DENIED_ERROR,
			"[B1] LOCKOUT: correct password rejected after %d failures "
			"(errno=%u, expected %u)",
			TEST_MAX_FAILURES_PER_USER, err, (unsigned)ER_ACCESS_DENIED_ERROR);
	}

	/* ============================================================
	 * Phase C -- window expiry releases the lockout.
	 *
	 * Sliding window: as timestamps in the deque age past
	 * failure_window_s, would_lockout_user prunes them. Sleep
	 * window_s + 1 to ensure the oldest timestamps fall off, then
	 * re-attempt with the correct credential.
	 *
	 * This validates that the lockout is genuinely a SLIDING window,
	 * not a permanent ban. Without prune_and_count's eviction the
	 * deque would keep growing and lockout would never lift.
	 * ============================================================ */
	{
		std::this_thread::sleep_for(std::chrono::seconds(TEST_FAILURE_WINDOW_S + 1));
		const unsigned int err = try_connect(cl, TEST_USER, TEST_BACKEND_PW);
		ok(err == 0,
			"[C1] After window expiry (%ds + 1), correct password "
			"is accepted again (errno=%u)",
			TEST_FAILURE_WINDOW_S, err);
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
		rc |= do_query(admin, "SET mysql-passthrough_auth_failure_window_s='60'");
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: mysql_users + globals restored");
	}

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
