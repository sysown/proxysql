/**
 * @file mysql_watchdog_test-t.cpp
 * @brief Test ProxySQL watchdog heartbeat for MySQL threads.
 * @details This test runs ProxySQL's internal test commands:
 *  - PROXYSQLTEST 55 0 → MySQL watchdog test
 */

#include <string>
#include <string.h>
#include "mysql.h"
#include "tap.h"
#include "command_line.h"

using std::string;

CommandLine cl;

bool run_watchdog_test(MYSQL* conn, int test_arg, const char* test_label) {
	char query[64];
	snprintf(query, sizeof(query), "PROXYSQLTEST 55 %d", test_arg);

	diag("Running %s watchdog test...", test_label);
	if (mysql_query(conn, query)) {
		std::string error_msg = mysql_error(conn);
		if (error_msg.find("Invalid test") != std::string::npos) {
			ok(true, "ProxySQL is not compiled in Debug mode. Skipping %s watchdog test", test_label);
			return true;
		} else {
			diag("Error running %s watchdog test: %s", test_label, error_msg.c_str());
			ok(false, "Watchdog test %s failed", test_label);
			return false;
		}
	}
	ok(true, "%s watchdog test executed successfully", test_label);
	return true;
}

int main() {
	if (cl.getEnv()) {
		diag("Failed to get required environment variables");
		return -1;
	}

	plan(1);  // One test for MySQL

	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "Error: mysql_init failed\n");
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "Connection error: %s\n", mysql_error(proxysql_admin));
		return -1;
	}

	run_watchdog_test(proxysql_admin, 0, "MySQL");

	mysql_close(proxysql_admin);
	return exit_status();
}
