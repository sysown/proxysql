/**
 * @file test_passthrough_auth_ephemeral-t.cpp
 * @brief End-to-end test for ephemeral pass-through credentials
 *        (mysql-passthrough_auth_ephemeral_pattern and
 *        mysql-passthrough_auth_ephemeral_backend_credential_file).
 *
 * An ephemeral credential is short-lived and differs per client -- for
 * example a signed, expiring token validated by a backend auth plugin.
 * The pass-through cache holds one cleartext per username, so it cannot
 * represent an account that has several valid credentials at once, and
 * a cached token would outlive its validity.
 *
 * The test needs no token plugin. MySQL dual passwords
 * (ALTER USER ... RETAIN CURRENT PASSWORD) give one account two valid
 * credentials at the same time, and DISCARD OLD PASSWORD makes one of
 * them "expire".
 *
 * Part 1 -- ephemeral credentials are verified on every connection and
 * never cached:
 *
 *   1. Backend user with two valid passwords, both matching the pattern.
 *   2. Connect with A, then B, then A again: all three succeed. Without
 *      the pattern the second one is rejected by ProxySQL because the
 *      first one is cached.
 *   3. No cache row exists for the user, and @c cache_hits did not move.
 *   4. A password that does not match the pattern is still cached.
 *
 * Part 2 -- sessions that authenticated with an ephemeral credential use
 * the standing backend credential for later backend connections:
 *
 *   5. Backend user whose primary password is the standing credential
 *      and whose secondary password matches the pattern. The standing
 *      credential is written to a file ProxySQL can read.
 *   6. A client connects with the ephemeral password, then the backend
 *      discards it. A query that forces a fresh backend connection on
 *      that session still succeeds.
 *   7. A new client presenting the discarded password is rejected.
 *   8. The standing credential is rotated on the backend and in the
 *      file: the existing session keeps working.
 *   9. With the file variable unset, the same sequence ends with the
 *      backend rejecting the session's own (discarded) credential.
 *
 * The file is written under ProxySQL's data directory, which the test
 * runner shares with the ProxySQL container. Override the directory
 * with TAP_PROXYSQL_DATADIR when running outside the isolated harness.
 */
#include <cstdio>
#include <cstring>
#include <string>

#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

static constexpr const char* USER_MULTI    = "tap_pt_eph_multi_user";
static constexpr const char* USER_PLAIN    = "tap_pt_eph_plain_user";
static constexpr const char* USER_STANDING = "tap_pt_eph_standing_user";

static constexpr const char* EPH_A      = "eph-t0ken-AAAA-1111";
static constexpr const char* EPH_B      = "eph-t0ken-BBBB-2222";
static constexpr const char* EPH_C      = "eph-t0ken-CCCC-3333";
static constexpr const char* PLAIN_PW   = "pl4in-passw0rd-n0-match!";
static constexpr const char* STANDING_1 = "st4nding-backend-cred-1!";
static constexpr const char* STANDING_2 = "st4nding-backend-cred-2!";

static constexpr const char* FRESH_BACKEND_QUERY = "SELECT /* ;create_new_connection=1 */ 1";

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
 * @brief Open a frontend session over TLS (pass-through needs the
 *        caching_sha2_password full-auth path). Returns NULL and sets
 *        @p cerr on failure.
 */
static MYSQL* frontend_connect(const CommandLine& cl, const char* user, const char* pw, unsigned int& cerr) {
	MYSQL* m = mysql_init(NULL);
	mysql_options(m, MYSQL_DEFAULT_AUTH, "caching_sha2_password");
	mysql_ssl_set(m, NULL, NULL, NULL, NULL, NULL);
	if (!mysql_real_connect(m, cl.host, user, pw, NULL, cl.port, NULL, CLIENT_SSL)) {
		cerr = mysql_errno(m);
		mysql_close(m);
		return NULL;
	}
	cerr = 0;
	return m;
}

/** @brief Run @p query on an open session; returns the errno (0 on success). */
static unsigned int run_query(MYSQL* m, const char* query) {
	if (mysql_query(m, query)) {
		return mysql_errno(m);
	}
	MYSQL_RES* r = mysql_store_result(m);
	if (r) mysql_free_result(r);
	return 0;
}

/** @brief Connect, run SELECT 1, disconnect. Returns { connect_errno, query_errno }. */
static std::pair<unsigned int, unsigned int> connect_and_query(
	const CommandLine& cl, const char* user, const char* pw
) {
	unsigned int cerr = 0;
	MYSQL* m = frontend_connect(cl, user, pw, cerr);
	if (!m) return { cerr, 0 };
	const unsigned int qerr = run_query(m, "SELECT 1");
	mysql_close(m);
	return { 0, qerr };
}

/** @brief Atomically replace @p path with one line holding @p value. */
static bool write_credential_file(const string& path, const char* value) {
	const string tmp = path + ".tmp";
	FILE* f = fopen(tmp.c_str(), "w");
	if (!f) {
		diag("Cannot open %s: %s", tmp.c_str(), strerror(errno));
		return false;
	}
	const bool wrote = fprintf(f, "%s\n", value) > 0;
	fclose(f);
	if (!wrote || rename(tmp.c_str(), path.c_str()) != 0) {
		diag("Cannot write %s: %s", path.c_str(), strerror(errno));
		return false;
	}
	return true;
}

/** @brief (Re)create @p user on the backend with a single password. */
static bool provision_user(MYSQL* backend, const char* user, const char* pw) {
	do_query(backend, string("DROP USER IF EXISTS '") + user + "'@'%'");
	return
		do_query(backend,
			string("CREATE USER '") + user + "'@'%' "
			"IDENTIFIED WITH 'caching_sha2_password' BY '" + pw + "'") == EXIT_SUCCESS &&
		do_query(backend,
			string("GRANT SELECT ON *.* TO '") + user + "'@'%'") == EXIT_SUCCESS;
}

/** @brief Set a new primary password and keep the current one as secondary. */
static bool add_primary_password(MYSQL* backend, const char* user, const char* pw) {
	return do_query(backend,
		string("ALTER USER '") + user + "'@'%' IDENTIFIED BY '" + pw + "' RETAIN CURRENT PASSWORD")
		== EXIT_SUCCESS;
}

static bool discard_old_password(MYSQL* backend, const char* user) {
	return do_query(backend,
		string("ALTER USER '") + user + "'@'%' DISCARD OLD PASSWORD") == EXIT_SUCCESS;
}

int main() {
	CommandLine cl;

	plan(22);

	if (cl.getEnv()) {
		return exit_status();
	}

	const string datadir = get_env_str("TAP_PROXYSQL_DATADIR", "/var/lib/proxysql");
	const string cred_file = datadir + "/tap_pt_ephemeral_backend_credential";

	MYSQL* backend = mysql_init(NULL);
	ok(mysql_real_connect(backend, cl.mysql_host, cl.mysql_username, cl.mysql_password,
			NULL, cl.mysql_port, NULL, 0) != NULL,
		"Connected to backend MySQL");

	MYSQL* admin = mysql_init(NULL);
	ok(mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
			NULL, cl.admin_port, NULL, 0) != NULL,
		"Connected to ProxySQL admin");

	do_query(admin,
		string("UPDATE mysql_servers SET status='ONLINE', use_ssl=1 WHERE hostgroup_id=")
		+ std::to_string(MYSQL8_HG));
	do_query(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	/* -------- backend users -------- */
	bool users_ok = true;
	/* USER_MULTI: secondary = EPH_A, primary = EPH_B -- both valid, both ephemeral. */
	users_ok &= provision_user(backend, USER_MULTI, EPH_A);
	users_ok &= add_primary_password(backend, USER_MULTI, EPH_B);
	/* USER_PLAIN: one ordinary password that does not match the pattern. */
	users_ok &= provision_user(backend, USER_PLAIN, PLAIN_PW);
	/* USER_STANDING: secondary = EPH_C (ephemeral), primary = STANDING_1. */
	users_ok &= provision_user(backend, USER_STANDING, EPH_C);
	users_ok &= add_primary_password(backend, USER_STANDING, STANDING_1);
	ok(users_ok, "Backend users provisioned (dual passwords)");

	/* -------- empty-pw rows + pass-through config -------- */
	for (const char* u : { USER_MULTI, USER_PLAIN, USER_STANDING }) {
		do_query(admin, string("DELETE FROM mysql_users WHERE username='") + u + "'");
		do_query(admin,
			string("INSERT INTO mysql_users (username, password, default_hostgroup, active) VALUES ('")
			+ u + "', '', " + std::to_string(MYSQL8_HG) + ", 1)");
	}
	do_query(admin, "LOAD MYSQL USERS TO RUNTIME");

	bool cfg_ok = true;
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_enabled='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_require_tls='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_empty_password='true'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-default_authentication_plugin='caching_sha2_password'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='10000'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10000'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-connect_retries_on_failure='0'") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_ephemeral_pattern=''") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "SET mysql-passthrough_auth_ephemeral_backend_credential_file=''") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE") == EXIT_SUCCESS);
	cfg_ok &= (do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == EXIT_SUCCESS);
	ok(cfg_ok, "Pass-through configured, ephemeral pattern off");

	/* ============================================================
	 * Baseline: with the pattern off, the second valid credential is
	 * rejected because the first one is cached.
	 * ============================================================ */
	{
		const auto [c1, q1] = connect_and_query(cl, USER_MULTI, EPH_A);
		const auto [c2, q2] = connect_and_query(cl, USER_MULTI, EPH_B);
		ok(c1 == 0 && q1 == 0 && c2 == ER_ACCESS_DENIED_ERROR,
			"[baseline] pattern off: first credential cached, second valid one rejected "
			"(connect_errno=%u/%u)", c1, c2);
	}

	/* ============================================================
	 * Part 1: ephemeral credentials are verified per connection and
	 * never cached.
	 * ============================================================ */
	{
		bool rc = true;
		rc &= (do_query(admin, "SET mysql-passthrough_auth_ephemeral_pattern='eph-.*'") == EXIT_SUCCESS);
		rc &= (do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE") == EXIT_SUCCESS);
		rc &= (do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == EXIT_SUCCESS);
		ok(rc, "Ephemeral pattern set to 'eph-.*'");
	}
	const int64_t hits_before = read_metric(admin, "cache_hits");
	const int64_t probes_before = read_metric(admin, "probes_ok");
	{
		const auto [c1, q1] = connect_and_query(cl, USER_MULTI, EPH_A);
		const auto [c2, q2] = connect_and_query(cl, USER_MULTI, EPH_B);
		const auto [c3, q3] = connect_and_query(cl, USER_MULTI, EPH_A);
		ok(c1 == 0 && q1 == 0 && c2 == 0 && q2 == 0 && c3 == 0 && q3 == 0,
			"[1] two valid ephemeral credentials for one user both work, in any order "
			"(connect_errno=%u/%u/%u, query_errno=%u/%u/%u)", c1, c2, c3, q1, q2, q3);
	}
	ok(cache_entry_count_for(admin, USER_MULTI) == 0,
		"[1] no cache entry for the ephemeral user");
	{
		const int64_t hits_after = read_metric(admin, "cache_hits");
		const int64_t probes_after = read_metric(admin, "probes_ok");
		ok(hits_after == hits_before && probes_after - probes_before == 3,
			"[1] every connection was verified against the backend "
			"(cache_hits %lld -> %lld, probes_ok %lld -> %lld)",
			(long long)hits_before, (long long)hits_after,
			(long long)probes_before, (long long)probes_after);
	}
	{
		const auto [c1, q1] = connect_and_query(cl, USER_MULTI, "eph-wr0ng-credential");
		ok(c1 == ER_ACCESS_DENIED_ERROR,
			"[1] a wrong ephemeral credential is rejected (connect_errno=%u)", c1);
	}
	{
		const auto [c1, q1] = connect_and_query(cl, USER_PLAIN, PLAIN_PW);
		const int64_t hits_mid = read_metric(admin, "cache_hits");
		const auto [c2, q2] = connect_and_query(cl, USER_PLAIN, PLAIN_PW);
		const int64_t hits_end = read_metric(admin, "cache_hits");
		ok(c1 == 0 && q1 == 0 && c2 == 0 && q2 == 0
				&& cache_entry_count_for(admin, USER_PLAIN) == 1 && hits_end - hits_mid == 1,
			"[1] a credential that does not match the pattern is still cached "
			"(connect_errno=%u/%u, cache_hits +%lld)", c1, c2, (long long)(hits_end - hits_mid));
	}

	/* ============================================================
	 * Part 2: standing backend credential.
	 * ============================================================ */
	ok(write_credential_file(cred_file, STANDING_1),
		"[2] standing credential written to %s", cred_file.c_str());
	{
		bool rc = true;
		rc &= (do_query(admin,
			string("SET mysql-passthrough_auth_ephemeral_backend_credential_file='") + cred_file + "'")
			== EXIT_SUCCESS);
		rc &= (do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == EXIT_SUCCESS);
		ok(rc, "[2] standing credential file configured");
	}
	{
		unsigned int cerr = 0;
		MYSQL* sess = frontend_connect(cl, USER_STANDING, EPH_C, cerr);
		ok(sess != NULL && run_query(sess, "SELECT 1") == 0,
			"[2] client authenticated with the ephemeral credential (connect_errno=%u)", cerr);

		/* The ephemeral credential expires on the backend. */
		ok(discard_old_password(backend, USER_STANDING),
			"[2] backend discarded the ephemeral credential");

		const unsigned int q1 = sess ? run_query(sess, FRESH_BACKEND_QUERY) : 1;
		ok(q1 == 0,
			"[2] existing session opens a fresh backend connection with the standing credential "
			"(query_errno=%u)", q1);

		const auto [c2, q2] = connect_and_query(cl, USER_STANDING, EPH_C);
		ok(c2 == ER_ACCESS_DENIED_ERROR,
			"[2] a new client presenting the expired credential is rejected (connect_errno=%u)", c2);

		/* Rotate the standing credential: backend first, then the file. */
		bool rot = do_query(backend,
			string("ALTER USER '") + USER_STANDING + "'@'%' IDENTIFIED BY '" + STANDING_2 + "'")
			== EXIT_SUCCESS;
		rot &= write_credential_file(cred_file, STANDING_2);
		const unsigned int q3 = sess ? run_query(sess, FRESH_BACKEND_QUERY) : 1;
		ok(rot && q3 == 0,
			"[2] after rotating the standing credential the existing session keeps working "
			"(query_errno=%u)", q3);

		ok(cache_entry_count_for(admin, USER_STANDING) == 0,
			"[2] no cache entry for the ephemeral user");
		if (sess) mysql_close(sess);
	}

	/* ============================================================
	 * Without the file the session keeps its own credential, so a
	 * fresh backend connection fails once that credential expired.
	 * ============================================================ */
	{
		bool rc = true;
		rc &= (do_query(admin, "SET mysql-passthrough_auth_ephemeral_backend_credential_file=''") == EXIT_SUCCESS);
		rc &= (do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == EXIT_SUCCESS);
		/* primary = EPH_C again (ephemeral), no standing credential in play. */
		rc &= provision_user(backend, USER_STANDING, EPH_A);
		rc &= add_primary_password(backend, USER_STANDING, EPH_C);
		unsigned int cerr = 0;
		MYSQL* sess = frontend_connect(cl, USER_STANDING, EPH_A, cerr);
		rc &= (sess != NULL && run_query(sess, "SELECT 1") == 0);
		rc &= discard_old_password(backend, USER_STANDING);
		const unsigned int q1 = sess ? run_query(sess, FRESH_BACKEND_QUERY) : 0;
		ok(rc && q1 == ER_ACCESS_DENIED_ERROR,
			"[3] file unset: a fresh backend connection uses the session's own, now expired, credential "
			"(connect_errno=%u, query_errno=%u, expected %u)", cerr, q1, (unsigned)ER_ACCESS_DENIED_ERROR);
		if (sess) mysql_close(sess);
	}

	/* -------- cleanup -------- */
	{
		int rc = EXIT_SUCCESS;
		for (const char* u : { USER_MULTI, USER_PLAIN, USER_STANDING }) {
			rc |= do_query(backend, string("DROP USER IF EXISTS '") + u + "'@'%'");
		}
		ok(rc == EXIT_SUCCESS, "Cleanup: DROP USER on backend");
	}
	{
		int rc = EXIT_SUCCESS;
		for (const char* u : { USER_MULTI, USER_PLAIN, USER_STANDING }) {
			rc |= do_query(admin, string("DELETE FROM mysql_users WHERE username='") + u + "'");
		}
		rc |= do_query(admin, "PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE");
		rc |= do_query(admin, "LOAD MYSQL USERS TO RUNTIME");
		rc |= do_query(admin, "SET mysql-passthrough_auth_enabled='false'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_empty_password='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_require_tls='true'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_ephemeral_pattern=''");
		rc |= do_query(admin, "SET mysql-passthrough_auth_ephemeral_backend_credential_file=''");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_user='3'");
		rc |= do_query(admin, "SET mysql-passthrough_auth_max_failures_per_ip='10'");
		rc |= do_query(admin, "SET mysql-connect_retries_on_failure='10'");
		rc |= do_query(admin, "SET mysql-default_authentication_plugin='mysql_native_password'");
		rc |= do_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(rc == EXIT_SUCCESS, "Cleanup: globals restored");
	}
	unlink(cred_file.c_str());

	mysql_close(backend);
	mysql_close(admin);
	return exit_status();
}
