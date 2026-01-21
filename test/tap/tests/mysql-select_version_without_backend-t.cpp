/**
 * @file mysql-select_version_without_backend-t.cpp
 * @brief TAP test for validating SELECT VERSION() behavior with mysql-select_version_forwarding
 *
 * ## Overview
 *
 * This test validates the behavior of the `mysql-select_version_forwarding` variable
 * when ProxySQL has NO backend servers configured. This scenario tests how ProxySQL
 * handles SELECT VERSION() and SELECT @@VERSION queries when there are no available
 * backend connections to peek at.
 *
 * ## Background
 *
 * Since ProxySQL 3.0.4, SELECT VERSION() queries are intercepted by ProxySQL.
 * The `mysql-select_version_forwarding` variable controls this behavior with 4 modes:
 *
 * - Mode 0 (NEVER): Always return ProxySQL's own mysql-server_version
 * - Mode 1 (ALWAYS): Always proxy the query to a backend server
 * - Mode 2 (SMART_FALLBACK_INTERNAL): Try to get version from backend connection,
 *   fallback to ProxySQL's mysql-server_version if no connection available
 * - Mode 3 (SMART_FALLBACK_PROXY, default): Try to get version from backend connection,
 *   fallback to proxying the query if no connection available
 *
 * ## Test Scenarios
 *
 * This test runs TWO scenarios with NO backend servers configured:
 *
 * ### Scenario 1: Mode 3 (smart with fallback to proxying) - EXPECTED TO FAIL
 *
 * When `mysql-select_version_forwarding=3` and there are NO backend servers:
 * - ProxySQL tries to peek at backend connections to get the version
 * - No connections exist (no backends configured)
 * - Fallback behavior: ProxySQL attempts to proxy the query to a backend
 * - Result: Query FAILS because there is no backend to proxy to
 *
 * This test explicitly verifies that mode 3 behaves correctly when there are no
 * backends - it should attempt to proxy and fail, rather than returning an internal
 * version incorrectly.
 *
 * ### Scenario 2: Mode 2 (smart with fallback to internal) - EXPECTED TO SUCCEED
 *
 * When `mysql-select_version_forwarding=2` and there are NO backend servers:
 * - ProxySQL tries to peek at backend connections to get the version
 * - No connections exist (no backends configured)
 * - Fallback behavior: Return ProxySQL's mysql-server_version (internal version)
 * - Result: Query SUCCEEDS and returns the configured mysql-server_version
 *
 * This test verifies that mode 2 provides a safe fallback that allows queries
 * to succeed even when no backends are available.
 *
 * ## Test Execution Flow
 *
 * For each scenario:
 * 1. Set `mysql-select_version_forwarding` to the desired mode (3 or 2)
 * 2. Set `mysql-server_version` to a known test value (e.g., "8.4.6")
 * 3. Delete all backend servers (ensure no backends exist)
 * 4. Execute two queries:
 *    - "SELECT @@VERSION" - Returns ProxySQL's mysql-server_version
 *    - "SELECT VERSION()" - Behavior depends on mode
 * 5. Verify the results match the expected behavior for the mode
 *
 * ## Why Both Scenarios Matter
 *
 * - Mode 3 is the DEFAULT and provides the most accurate version information
 *   by ensuring clients get the real backend version or nothing. This is
 *   important for clients like SQLAlchemy that need to detect MariaDB vs MySQL.
 *
 * - Mode 2 provides a safer fallback that maintains availability at the cost
 *   of potentially returning less accurate version information when no backends
 *   are available.
 *
 * Testing both ensures the feature works correctly in all configurations and
 * prevents regressions in future versions.
 */

#include <unistd.h>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

#define MYSQL_TEST_SERVER_VERSION "8.4.6"
#define MYSQL_SET_SERVER_VERSION_QUERY "SET mysql-server_version='" MYSQL_TEST_SERVER_VERSION "'"

MYSQL* init_mysql_conn(char* host, char* user, char* pass, int port) {
	diag("Creating MySQL conn host=\"%s\" port=\"%d\" user=\"%s\"", host, port, user);

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		return nullptr;
	}

	if (!mysql_real_connect(mysql, host, user, pass, NULL, port, NULL, 0)) {
		return nullptr;
	}

	return mysql;
}

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY_T(mysql,q);
	return 0;
}

/**
 * @brief Test SELECT VERSION() behavior with a specific mode
 *
 * @param admin Admin connection for configuration
 * @param proxy Proxy connection for queries
 * @param mode The mysql-select_version_forwarding mode to test
 * @param expect_success Whether queries are expected to succeed
 * @return int 0 on success, EXIT_FAILURE on error
 */
int test_mode(MYSQL* admin, MYSQL* proxy, int mode, bool expect_success) {
	// Set the mode explicitly
	char set_mode_query[128];
	snprintf(set_mode_query, sizeof(set_mode_query),
		"SET mysql-select_version_forwarding=%d", mode);
	MYSQL_QUERY_T(admin, set_mode_query);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Ensure no backends exist
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	diag("=== Testing mode %d (expect %s) ===",
		mode,
		expect_success ? "SUCCESS" : "FAILURE");

	const char *version_get_queries[2] = {
		"SELECT @@VERSION",
		"SELECT VERSION()"
	};

	for (int i = 0; i < 2; i++) {
		MYSQL_ROW row = nullptr;
		string res_server_version;

		// Attempt to run the query
		int rc = run_q(proxy, version_get_queries[i]);

		if (rc == 0) {
			// Query succeeded - fetch result
			MYSQL_RES* proxy_res = mysql_store_result(proxy);

			row = mysql_fetch_row(proxy_res);
			if (row) {
				res_server_version = row[0];
			}

			mysql_free_result(proxy_res);
		}

		// Verify result matches expected behavior
		if (expect_success) {
			// Mode 2: Query should succeed and return ProxySQL's version
			bool test_passed = row && (res_server_version == MYSQL_TEST_SERVER_VERSION);
			ok(test_passed,
				"Mode %d: %s should return '%s' - got '%s'",
				mode,
				version_get_queries[i],
				MYSQL_TEST_SERVER_VERSION,
				res_server_version.c_str());
		} else {
			// Mode 3: Query should FAIL (no backend to proxy to)
			bool test_passed = (row == nullptr);
			ok(test_passed,
				"Mode %d: %s should FAIL (no backend) - %s",
				mode,
				version_get_queries[i],
				row ? "UNEXPECTED SUCCESS" : "correctly failed");
		}
	}

	return 0;
}

int main(int argc, char** argv) {
	// We have 2 queries × 2 modes = 4 tests total
	plan(4);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_username, cl.admin_password, cl.admin_port);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	// Set the ProxySQL version that will be returned for internal fallback
	MYSQL_QUERY_T(admin, MYSQL_SET_SERVER_VERSION_QUERY);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl.host, cl.username, cl.password, cl.port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		mysql_close(admin);
		return exit_status();
	}

	// Scenario 1: Mode 3 (smart with fallback to proxying) - EXPECTED TO FAIL
	// With no backends, mode 3 will try to proxy the query and fail
	test_mode(admin, proxy, 3, false);

	// Scenario 2: Mode 2 (smart with fallback to internal) - EXPECTED TO SUCCEED
	// With no backends, mode 2 will fall back to returning mysql-server_version
	test_mode(admin, proxy, 2, true);

	mysql_close(admin);
	mysql_close(proxy);

	return exit_status();
}
