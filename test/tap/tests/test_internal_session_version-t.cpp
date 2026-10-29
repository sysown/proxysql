/**
 * @file test_internal_session_version-t.cpp
 * @brief Verifies that 'PROXYSQL INTERNAL SESSION' reports the ProxySQL version.
 * @details Feature request #5859: the JSON returned by 'PROXYSQL INTERNAL SESSION'
 *   should include a 'version' field carrying the running ProxySQL version. This
 *   test checks that:
 *
 *   1. The 'version' key is present in the 'PROXYSQL INTERNAL SESSION' output.
 *   2. Its value is a non-empty string.
 *   3. Its value matches the 'admin-version' global variable reported by the
 *      Admin interface (both are sourced from the same PROXYSQL_VERSION macro).
 */

#include <cstring>
#include <string>
#include <stdio.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(3);

	// Connection to the ProxySQL MySQL interface (issues 'PROXYSQL INTERNAL SESSION')
	MYSQL* proxysql_mysql = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}

	// Connection to the ProxySQL Admin interface (reads 'admin-version')
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		mysql_close(proxysql_mysql);
		return EXIT_FAILURE;
	}

	// Fetch the reference version from Admin
	std::string admin_version;
	MYSQL_QUERY(proxysql_admin, "SELECT variable_value FROM global_variables WHERE variable_name='admin-version'");
	{
		MYSQL_RES* res = mysql_store_result(proxysql_admin);
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) {
			admin_version = row[0];
		}
		mysql_free_result(res);
	}
	diag("Admin reports 'admin-version' = '%s'", admin_version.c_str());

	// Fetch and inspect 'PROXYSQL INTERNAL SESSION'
	json j = fetch_internal_session(proxysql_mysql, false);

	bool has_version = j.contains("version") && j["version"].is_string();
	ok(has_version, "'PROXYSQL INTERNAL SESSION' should contain a string 'version' field");

	std::string session_version = has_version ? j["version"].get<std::string>() : std::string();
	diag("'PROXYSQL INTERNAL SESSION' reports 'version' = '%s'", session_version.c_str());

	ok(!session_version.empty(), "'version' field should be a non-empty string");

	ok(
		session_version == admin_version,
		"'version' field ('%s') should match 'admin-version' ('%s')",
		session_version.c_str(), admin_version.c_str()
	);

	mysql_close(proxysql_admin);
	mysql_close(proxysql_mysql);

	return exit_status();
}
