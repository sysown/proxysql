/**
 * @file reg_test_5363_admin_monitor_caching_sha2-t.cpp
 * @brief Regression test for issue #5363 -- the 'mysql-monitor_*' credential could
 *   not authenticate on the Admin interface under 'caching_sha2_password'.
 *
 * @details
 * 'mysql-monitor_username' / 'mysql-monitor_password' is not stored in
 * 'GloMyAuth'. MySQL_Protocol::PPHR_verify_password() therefore reaches it via
 * its 'vars1.password == NULL' branch, and PPHR_5passwordFalse_0() is the only
 * code that authenticates it. That function used to be hardcoded to the
 * mysql_native_password scramble -- a SHA1 'proxy_scramble' compared over 20
 * bytes -- so under 'caching_sha2_password', where the client's fast-auth
 * response is a 32-byte SHA256-derived value, it could never match. Kubernetes
 * liveness/readiness probes and metrics exporters connecting to :6032 as the
 * monitor user failed with 'Access denied'. TLS was not a workaround, because
 * the function returned false without ever sending 'perform full authentication'.
 *
 * HOW THE ASSERTION WORKS
 *
 *   The monitor credential is additionally subject to a locality restriction, so
 *   a connection from off-box is refused even when the password is correct. That
 *   turns out to be exactly what makes this testable from CI, because the two
 *   rejections are distinguishable and happen at different stages:
 *
 *     1040 ER_HOST_NOT_PRIVILEGED  "User 'monitor' can only connect locally"
 *          -> authentication SUCCEEDED; rejected afterwards by the locality check
 *     1045 ER_ACCESS_DENIED_ERROR  "Access denied for user 'monitor'"
 *          -> authentication FAILED
 *
 *   So the regression is precisely "correct password yields 1045 instead of
 *   1040 under caching_sha2_password". Before the fix the caching_sha2 rows
 *   below returned 1045; they must now return 1040.
 *
 *   This avoids needing to run the client inside the ProxySQL container, which a
 *   TAP test cannot do. The developer-facing reproduction in
 *   test/repro/reg_test_5363_admin_monitor_caching_sha2.bash does connect locally
 *   and asserts a real successful login; the two are complementary.
 *
 * SCOPE
 *   No mysql_users rows are involved, and no admin credential named after the
 *   monitor user exists -- both are asserted as preconditions. Issue #5985
 *   Finding 1 (a mysql_users row shadowing a same-named Admin credential) is a
 *   different problem and would confound this result.
 *
 * The test restores 'mysql-default_authentication_plugin' and
 * 'mysql-monitor_password' before exiting, including on failure paths: the
 * group runs against a shared instance.
 */

#include <cstring>
#include <string>
#include <vector>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;
using std::vector;

static const char* MON_USER = "monitor";
static const char* MON_PASS = "monitorpass";

/* Rejected after a successful authentication by the locality check. */
static const unsigned int ERR_ONLY_LOCAL   = 1040;
/* Rejected during authentication. */
static const unsigned int ERR_ACCESS_DENIED = 1045;

struct case_t {
	const char* plugin;
	bool use_tls;
	const char* pass;
	unsigned int exp_errno;
	const char* desc;
};

/**
 * @brief Attempt an Admin login and return the resulting mysql_errno().
 * @return 0 when the connection unexpectedly succeeds.
 */
static unsigned int try_admin_login(
	const CommandLine& cl, const char* user, const char* pass, bool use_tls
) {
	MYSQL* conn = mysql_init(NULL);
	if (conn == NULL) { return 0; }

	// The TAP suite links MariaDB Connector/C, which has no MYSQL_OPT_SSL_MODE;
	// mysql_ssl_set + CLIENT_SSL is the idiom used elsewhere in these tests.
	unsigned long client_flags = 0;
	if (use_tls) {
		mysql_ssl_set(conn, NULL, NULL, NULL, NULL, NULL);
		client_flags |= CLIENT_SSL;
	}

	unsigned int err = 0;
	if (!mysql_real_connect(conn, cl.admin_host, user, pass, NULL, cl.admin_port, NULL, client_flags)) {
		err = mysql_errno(conn);
		diag("  login user='%s' tls=%s -> errno=%u '%s'",
			user, use_tls ? "yes" : "no", err, mysql_error(conn));
	} else {
		diag("  login user='%s' tls=%s -> CONNECTED (unexpected)", user, use_tls ? "yes" : "no");
	}

	mysql_close(conn);
	return err;
}

static int set_var(MYSQL* admin, const char* name, const char* value, const char* load_stmt) {
	const string q {
		string("UPDATE global_variables SET variable_value='") + value +
		"' WHERE variable_name='" + name + "'"
	};
	MYSQL_QUERY_T(admin, q.c_str());
	MYSQL_QUERY_T(admin, load_stmt);
	return EXIT_SUCCESS;
}

int main() {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const vector<case_t> CASES {
		// Baseline: this already worked before the fix.
		{ "mysql_native_password",  false, MON_PASS, ERR_ONLY_LOCAL,
		  "native/plaintext, correct password -> authenticated (1040 locality)" },
		{ "mysql_native_password",  true,  MON_PASS, ERR_ONLY_LOCAL,
		  "native/TLS, correct password -> authenticated (1040 locality)" },
		{ "mysql_native_password",  false, "WRONGPASS", ERR_ACCESS_DENIED,
		  "native/plaintext, wrong password -> rejected (1045)" },

		// The regression: these returned 1045 before the fix.
		{ "caching_sha2_password",  false, MON_PASS, ERR_ONLY_LOCAL,
		  "caching_sha2/plaintext, correct password -> authenticated (1040 locality)" },
		{ "caching_sha2_password",  true,  MON_PASS, ERR_ONLY_LOCAL,
		  "caching_sha2/TLS, correct password -> authenticated (1040 locality)" },
		{ "caching_sha2_password",  false, "WRONGPASS", ERR_ACCESS_DENIED,
		  "caching_sha2/plaintext, wrong password -> rejected (1045)" },
		{ "caching_sha2_password",  true,  "WRONGPASS", ERR_ACCESS_DENIED,
		  "caching_sha2/TLS, wrong password -> rejected (1045)" },
	};

	// 1 admin connection + 2 preconditions + the cases + 2 restore checks
	plan(1 + 2 + static_cast<int>(CASES.size()) + 2);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}
	ok(true, "Connected to ProxySQL Admin at %s:%d", cl.admin_host, cl.admin_port);

	// Remember what to put back.
	string orig_plugin {};
	string orig_mon_pass {};
	{
		MYSQL_QUERY_T(admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-default_authentication_plugin'");
		MYSQL_RES* r = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(r);
		if (row && row[0]) { orig_plugin = row[0]; }
		mysql_free_result(r);

		MYSQL_QUERY_T(admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-monitor_password'");
		r = mysql_store_result(admin);
		row = mysql_fetch_row(r);
		if (row && row[0]) { orig_mon_pass = row[0]; }
		mysql_free_result(r);
	}
	diag("Saved mysql-default_authentication_plugin='%s', mysql-monitor_password='%s'",
		orig_plugin.c_str(), orig_mon_pass.c_str());

	// --- Preconditions ------------------------------------------------------
	{
		MYSQL_QUERY_T(admin,
			("SELECT COUNT(*) FROM runtime_mysql_users WHERE username='" + string(MON_USER) + "'").c_str());
		MYSQL_RES* r = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(r);
		const long n = (row && row[0]) ? strtol(row[0], NULL, 10) : -1;
		mysql_free_result(r);
		ok(n == 0, "No mysql_users row named '%s' (Finding 1 cannot interfere)   count:'%ld'", MON_USER, n);
	}
	{
		MYSQL_QUERY_T(admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-admin_credentials'");
		MYSQL_RES* r = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(r);
		const string creds { (row && row[0]) ? row[0] : "" };
		mysql_free_result(r);
		const bool clash = creds.find(string(MON_USER) + ":") != string::npos;
		ok(!clash, "No admin credential named '%s' (PPHR_5passwordFalse_0 is the path)   creds:'%s'",
			MON_USER, creds.c_str());
	}

	set_var(admin, "mysql-monitor_username", MON_USER, "LOAD MYSQL VARIABLES TO RUNTIME");
	set_var(admin, "mysql-monitor_password", MON_PASS, "LOAD MYSQL VARIABLES TO RUNTIME");

	// --- Cases --------------------------------------------------------------
	string cur_plugin {};
	for (const case_t& c : CASES) {
		if (cur_plugin != c.plugin) {
			set_var(admin, "mysql-default_authentication_plugin", c.plugin, "LOAD MYSQL VARIABLES TO RUNTIME");
			cur_plugin = c.plugin;
			diag("--- mysql-default_authentication_plugin = %s ---", c.plugin);
		}

		const unsigned int got = try_admin_login(cl, MON_USER, c.pass, c.use_tls);
		ok(got == c.exp_errno, "%s   expected errno:'%u', got:'%u'", c.desc, c.exp_errno, got);
	}

	// --- Restore ------------------------------------------------------------
	set_var(admin, "mysql-default_authentication_plugin",
		orig_plugin.empty() ? "mysql_native_password" : orig_plugin.c_str(),
		"LOAD MYSQL VARIABLES TO RUNTIME");
	set_var(admin, "mysql-monitor_password",
		orig_mon_pass.empty() ? "monitor" : orig_mon_pass.c_str(),
		"LOAD MYSQL VARIABLES TO RUNTIME");

	{
		MYSQL_QUERY_T(admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-default_authentication_plugin'");
		MYSQL_RES* r = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(r);
		const string now { (row && row[0]) ? row[0] : "" };
		mysql_free_result(r);
		ok(now == orig_plugin, "mysql-default_authentication_plugin restored   exp:'%s', got:'%s'",
			orig_plugin.c_str(), now.c_str());
	}
	{
		MYSQL_QUERY_T(admin, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-monitor_password'");
		MYSQL_RES* r = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(r);
		const string now { (row && row[0]) ? row[0] : "" };
		mysql_free_result(r);
		ok(now == orig_mon_pass, "mysql-monitor_password restored   exp:'%s', got:'%s'",
			orig_mon_pass.c_str(), now.c_str());
	}

	mysql_close(admin);
	return exit_status();
}
