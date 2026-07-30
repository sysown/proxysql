/**
 * @file test_passthrough_auth_misconfig_warning-t.cpp
 * @brief Verifies that ProxySQL emits a WARNING in proxysql.log when an
 *        operator publishes the most-dangerous pass-through-auth
 *        configuration (spec §7.1).
 *
 * The dangerous combination is:
 *
 *   mysql-passthrough_auth_enabled            = true
 *   mysql-passthrough_auth_unknown_users      = true
 *   mysql-passthrough_auth_username_pattern   = ""   (empty)
 *
 * That triple lets ANY username an attacker can guess be probed against
 * the backend in @c mysql-passthrough_default_hg with no allowlist
 * constraint -- effectively turning ProxySQL into a credential-stuffing
 * oracle for the backend. Commit a65414217 added a one-shot
 * proxy_warning in MySQL_Threads_Handler::commit() so operators see the
 * risk at LOAD MYSQL VARIABLES TO RUNTIME.
 *
 * This test verifies the warning actually fires by:
 *   1. publishing the dangerous combination via SET / LOAD,
 *   2. tailing proxysql.log and looking for a recognizable substring
 *      of the warning, with a short retry budget for log flush,
 *   3. then publishing a SAFE combination (set a non-empty pattern)
 *      and confirming the warning does NOT fire a second time.
 *
 * Admin-only test -- runs in the @c no-infra-g1 group like
 * test_passthrough_auth_admin-t.cpp and admin_set_credentials_logging-t.cpp.
 */
#include <cstring>
#include <fstream>
#include <string>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::fstream;
using std::string;

/* Watch the log up to ~2s (20 * 100ms) for the message to appear. */
static constexpr int MAX_LOG_CHECK_ATTEMPTS = 20;
static constexpr useconds_t LOG_CHECK_RETRY_DELAY_US = 100000;

/**
 * @brief Substring uniquely identifying the misconfig warning.
 *
 * Keep this in sync with the format string at
 * lib/MySQL_Thread.cpp::MySQL_Threads_Handler::commit(). If the
 * wording is changed there, update here -- the test exists to ensure
 * the warning actually appears, so a wording drift should be a
 * deliberate decision.
 */
static constexpr const char* WARNING_FINGERPRINT =
	"unknown_users=true with empty username_pattern";

/**
 * @brief Read a global variable's current value via SHOW.
 */
static bool read_var(MYSQL *admin, const string &name, string &out) {
	const string q =
		"SELECT variable_value FROM global_variables WHERE variable_name='" + name + "'";
	if (mysql_query(admin, q.c_str())) return false;
	MYSQL_RES *res = mysql_store_result(admin);
	if (!res) return false;
	MYSQL_ROW row = mysql_fetch_row(res);
	bool ok = false;
	if (row && row[0]) { out = row[0]; ok = true; }
	mysql_free_result(res);
	return ok;
}

/**
 * @brief Scan the proxysql log from the current read offset for
 *        @p fingerprint, retrying briefly to absorb buffered writes.
 *
 * Pre-condition: caller seeked the stream to the desired starting
 * offset (typically just before the SET / LOAD that should produce the
 * line). Returns true if found within the retry budget; the stream
 * position is left wherever the scan stopped.
 */
static bool wait_for_log_line(fstream &log, const string &fingerprint) {
	string line;
	for (int attempt = 0; attempt < MAX_LOG_CHECK_ATTEMPTS; ++attempt) {
		log.clear(log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
		while (getline(log, line)) {
			if (line.find(fingerprint) != string::npos) {
				return true;
			}
		}
		usleep(LOG_CHECK_RETRY_DELAY_US);
	}
	return false;
}

int main() {
	CommandLine cl;

	/*
	 * Plan:
	 *   1 admin connection
	 *   1 REGULAR_INFRA_DATADIR set
	 *   1 log opened
	 *   1 dangerous combo published
	 *   1 warning observed in log     <- LOAD-BEARING
	 *   1 safe combo published
	 *   1 warning NOT observed twice  <- secondary load-bearing
	 *   1 cleanup
	 */
	plan(8);

	if (cl.getEnv()) {
		return exit_status();
	}

	MYSQL *admin = mysql_init(NULL);
	const MYSQL *acr = mysql_real_connect(
		admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0
	);
	ok(acr != NULL, "Connected to ProxySQL admin at %s:%d", cl.admin_host, cl.admin_port);
	if (!acr) { mysql_close(admin); return exit_status(); }

	const string log_dir { get_env("REGULAR_INFRA_DATADIR") };
	ok(!log_dir.empty(), "REGULAR_INFRA_DATADIR env is set (got '%s')", log_dir.c_str());
	const string log_path { log_dir + "/proxysql.log" };
	fstream proxysql_log {};
	const int log_res =
		log_dir.empty() ? EXIT_FAILURE : open_file_and_seek_end(log_path, proxysql_log);
	ok(log_res == EXIT_SUCCESS, "Opened ProxySQL log at '%s'", log_path.c_str());
	if (log_res != EXIT_SUCCESS) {
		mysql_close(admin);
		return exit_status();
	}

	/*
	 * Phase 1: publish the dangerous combination.
	 *
	 * SET each variable independently so the SETs themselves don't
	 * trigger a partial-state warning. The single warning we're
	 * looking for fires inside MySQL_Threads_Handler::commit() on the
	 * "LOAD MYSQL VARIABLES TO RUNTIME" call that publishes all four
	 * SETs at once.
	 */
	bool dangerous_set_ok = true;
	dangerous_set_ok &= (mysql_query(admin, "SET mysql-passthrough_auth_enabled='true'") == 0);
	dangerous_set_ok &= (mysql_query(admin, "SET mysql-passthrough_auth_unknown_users='true'") == 0);
	dangerous_set_ok &= (mysql_query(admin, "SET mysql-passthrough_auth_username_pattern=''") == 0);
	dangerous_set_ok &= (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == 0);
	ok(dangerous_set_ok, "Published dangerous combination via SET + LOAD");

	const bool warning_seen = wait_for_log_line(proxysql_log, WARNING_FINGERPRINT);
	ok(warning_seen,
		"proxysql.log contains the misconfig warning fingerprint '%s'",
		WARNING_FINGERPRINT);

	/*
	 * Phase 2: publish a SAFE configuration. The warning should NOT
	 * fire a second time (the misconfig predicate evaluates to
	 * false now). Mark the current log position and rescan after the
	 * LOAD; if a new warning line appears within the retry budget,
	 * the predicate is over-eager.
	 *
	 * We pick a permissive but non-empty pattern; the security value
	 * isn't tested here -- only the absence of the warning.
	 */
	const std::streampos pos_before_safe = proxysql_log.tellg();
	bool safe_set_ok = true;
	safe_set_ok &= (mysql_query(admin, "SET mysql-passthrough_auth_username_pattern='^.*$'") == 0);
	safe_set_ok &= (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME") == 0);
	ok(safe_set_ok, "Published safe combination (non-empty pattern) via SET + LOAD");

	/*
	 * Wait long enough for any warning that WOULD fire to have been
	 * written. Then seek back to pos_before_safe and scan -- if
	 * WARNING_FINGERPRINT appears in the new tail, the predicate
	 * over-fired.
	 */
	usleep(MAX_LOG_CHECK_ATTEMPTS * LOG_CHECK_RETRY_DELAY_US);
	proxysql_log.clear();
	proxysql_log.seekg(pos_before_safe);
	bool spurious_warning = false;
	string line;
	while (getline(proxysql_log, line)) {
		if (line.find(WARNING_FINGERPRINT) != string::npos) {
			spurious_warning = true;
			break;
		}
	}
	ok(!spurious_warning,
		"Warning did NOT re-fire after the safe LOAD (pattern non-empty)");

	/* -------- cleanup -------- */
	{
		int rc = EXIT_SUCCESS;
		if (mysql_query(admin, "SET mysql-passthrough_auth_enabled='false'")) rc = EXIT_FAILURE;
		if (mysql_query(admin, "SET mysql-passthrough_auth_unknown_users='false'")) rc = EXIT_FAILURE;
		if (mysql_query(admin, "SET mysql-passthrough_auth_username_pattern=''")) rc = EXIT_FAILURE;
		if (mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME")) rc = EXIT_FAILURE;
		ok(rc == EXIT_SUCCESS, "Cleanup: restored safe defaults");
	}

	if (proxysql_log.is_open()) proxysql_log.close();
	mysql_close(admin);
	return exit_status();
}
