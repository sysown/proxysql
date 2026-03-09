/**
 * @file test_unsupported_queries-t.cpp
 * @brief Test to check that unsupported queries, and queries that can be
 *   enabled or disabled via configuration variables, return the expected error
 *   codes, and perform correctly when enabled.
 */

#include <cstring>
#include <functional>
#include <vector>
#include <tuple>
#include <string>
#include <stdio.h>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "command_line.h"
#include "json.hpp"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;

/**
 * @brief List of the pairs holding the unsupported queries to be executed by ProxySQL
 *   together with the error code that they should return.
 */
std::vector<std::tuple<std::string, int, std::string>> unsupported_queries {
	std::make_tuple<std::string, int, std::string>(
		"LOAD DATA LOCAL INFILE",
		1047,
		"Unsupported 'LOAD DATA LOCAL INFILE' command"
	),
	std::make_tuple<std::string, int, std::string>(
		"LOAD DATA LOCAL INFILE 'data.txt' INTO TABLE db.test_table",
		1047,
		"Unsupported 'LOAD DATA LOCAL INFILE' command"
	),
	std::make_tuple<std::string, int, std::string>(
		"LOAD DATA LOCAL INFILE '/tmp/test.txt' INTO TABLE test IGNORE 1 LINES",
		1047,
		"Unsupported 'LOAD DATA LOCAL INFILE' command"
	),
};

/**
 * @brief Type holding the required information for identifying, enabling and
 *   disabling a query which support can be enabled and disabled by ProxySQL.
 */
using query_test_info =
	std::tuple<
		// Query to be tested
		std::string,
		// Variable name enabling / disabling the query
		std::string,
		// Value for enabling the query
		std::string,
		// Value for diabling the query
		std::string,
		// Expected error code in case of failure
		int,
		// Function performing an internal 'ok' test checking that the
		// enabled / disabled query responds as expected
		std::function<void(const CommandLine&, MYSQL*, int, bool)>
	>;

/**
 * @brief Enable the query based using the information supplied in the
 *   'query_info' parameter, and verifies that the value of the query has properly
 *   change at runtime.
 */
bool enable_query(MYSQL* proxysql_admin, const query_test_info& query_info, bool enable=true) {
	std::string exp_var_value {};
	if (enable == true) {
		exp_var_value =  std::get<2>(query_info);
	} else {
		exp_var_value =  std::get<3>(query_info);
	}

	std::vector<std::string> enabling_queries {
		"SET " + std::get<1>(query_info) + " = " + exp_var_value,
		"LOAD MYSQL VARIABLES TO RUNTIME"
	};

	bool success = true;
	for (const auto& query : enabling_queries) {
		diag("Admin Query: %s", query.c_str());
		if (mysql_query(proxysql_admin, query.c_str())) {
			diag("ERROR: ProxySQL Admin Error: %s", mysql_error(proxysql_admin));
			success = false;
			break;
		}
	}
	ok(success, "%s query '%s' should succeed.", (enable ? "Enabling" : "Disabling"), std::get<0>(query_info).c_str());
	return success;
}

// ******************* QUERIES TESTING FUNCTIONS ******************** //

const std::vector<std::string> prepare_table_queries {
	"CREATE DATABASE IF NOT EXISTS test",
	"DROP TABLE IF EXISTS test.load_data_local",
	"CREATE TABLE IF NOT EXISTS test.load_data_local ("
		" c1 INT NOT NULL AUTO_INCREMENT PRIMARY KEY, c2 VARCHAR(100), c3 VARCHAR(100))",
};

using mysql_res_row = std::vector<std::string>;

/**
 * @brief Helper function that performs the actual check for 'test_load_data_local_infile'.
 */
void helper_test_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	// PROVISIONING: Create shared directory and data file in /var/lib/proxysql
	// This ensures the server container can see the local file we want to load.
	string script_dst = "/var/lib/proxysql/load_data_local_datadir";
	string datafile = script_dst + "/insert_data.txt";
	
	diag("Step: Provisioning LOAD DATA test files...");
	diag("  - Target directory: %s", script_dst.c_str());
	string cmd = "mkdir -p " + script_dst + " && printf '1,\"a string\",100.20\n2,\"a string containing a , comma\",102.20\n3,\"a string containing a \\\" quote\",102.20\n4,\"a string containing a \\\", quote and comma\",102.20\n' > " + datafile + " && chmod -R 777 " + script_dst;
	
	if (system(cmd.c_str()) != 0) {
		diag("WARNING: Failed to provision test files to %s. Test may fail.", script_dst.c_str());
	}

	diag("Step: Preparing test table...");
	for (const auto& query : prepare_table_queries) {
		diag("  - Query: %s", query.c_str());
		if (mysql_query(proxysql, query.c_str())) {
			diag("  - ERROR: %s", mysql_error(proxysql));
		}
	}

	std::string t_load_data_command {
		"LOAD DATA LOCAL INFILE \"%s\" INTO TABLE test.load_data_local"
			" FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\\n'"
	};
	std::string load_data_command {};
	string_format(t_load_data_command, load_data_command, datafile.c_str());

	diag("Step: Executing LOAD DATA LOCAL INFILE...");
	diag("  - Query: %s", load_data_command.c_str());
	int load_data_res = mysql_query(proxysql, load_data_command.c_str());

	if (test_for_success) {
		if (load_data_res == EXIT_SUCCESS) {
			diag("  - SUCCESS: Query returned no error.");
		} else {
			diag("  - FAILURE: Query failed. Error: %s", mysql_error(proxysql));
		}

		diag("Step: Verifying data integrity via SELECT...");
		mysql_query(proxysql, "SELECT * /* ;hostgroup=0 */ FROM test.load_data_local");
		MYSQL_RES* result = mysql_store_result(proxysql);
		std::vector<mysql_res_row> rows_res { extract_mysql_rows(result) };
		std::vector<mysql_res_row> exp_rows {
			{ "1","a string","100.20" },
			{ "2","a string containing a , comma","102.20" },
			{ "3","a string containing a \" quote","102.20" },
			{ "4","a string containing a \", quote and comma","102.20" }
		};

		// Detailed row comparison output
		diag("  - Rows found: %zu, Expected: %zu", rows_res.size(), exp_rows.size());
		if (rows_res.size() != exp_rows.size()) {
			diag("  - ERROR: Row count mismatch!");
		}

		bool equal = (rows_res.size() == exp_rows.size());
		if (equal) equal = std::equal(exp_rows.begin(), exp_rows.end(), rows_res.begin());
		
		ok(equal, "The selected ROWS were equal to the expected ones");
		if (result) mysql_free_result(result);
	} else {
		int my_errno = mysql_errno(proxysql);
		diag("  - Expected error: %d, Actual error: %d", exp_err, my_errno);
		ok(my_errno == exp_err, "Query should fail with error %d. Actual: %d (%s)", exp_err, my_errno, mysql_error(proxysql));
	}
}

void test_verbose_error_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	diag("Sub-Test: Testing with mysql-verbose_query_error=true");
	MYSQL* admin = mysql_init(NULL);
	if (mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		mysql_query(admin, "SET mysql-verbose_query_error='true'");
		mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		helper_test_load_data_local_infile(cl, proxysql, exp_err, test_for_success);
		mysql_query(admin, "SET mysql-verbose_query_error='false'");
		mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		mysql_close(admin);
	}
}

void test_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	diag("Sub-Test: Standard LOAD DATA LOCAL INFILE test");
	helper_test_load_data_local_infile(cl, proxysql, exp_err, test_for_success);
}

void test_failing_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	diag("Sub-Test: Testing failure with non-existing file");
	std::string datafile = "/var/lib/proxysql/load_data_local_datadir/non_existing_file.txt";
	diag("  - Using invalid path: %s", datafile.c_str());

	for (const auto& query : prepare_table_queries) {
		mysql_query(proxysql, query.c_str());
	}

	std::string load_data_command = "LOAD DATA LOCAL INFILE \"" + datafile + "\" INTO TABLE test.load_data_local";
	int load_data_res = mysql_query(proxysql, load_data_command.c_str());

	if (test_for_success) {
		int my_errno = mysql_errno(proxysql);
		diag("  - Actual error returned: %d (%s)", my_errno, mysql_error(proxysql));
		ok((load_data_res != EXIT_SUCCESS) && my_errno == 2, "Query should fail with Errcode 2 (File not found)");
	} else {
		int my_errno = mysql_errno(proxysql);
		diag("  - Expected error: %d, Actual: %d", exp_err, my_errno);
		ok(my_errno == exp_err, "Query should fail with error %d. Actual: %d", exp_err, my_errno);
	}
}

/**
 * @brief List of queries which need to be check before performing the
 *   'unsupported' checks.
 */
std::vector<query_test_info> queries_tests_info {
	std::make_tuple<string, string, string, string, int, std::function<void(const CommandLine&, MYSQL*, int, bool)>>("LOAD DATA LOCAL INFILE", "mysql-enable_load_data_local_infile", "'true'", "'false'", 1047, test_load_data_local_infile),
	std::make_tuple<string, string, string, string, int, std::function<void(const CommandLine&, MYSQL*, int, bool)>>("LOAD DATA LOCAL INFILE", "mysql-enable_load_data_local_infile", "'true'", "'false'", 1047, test_failing_load_data_local_infile),
	std::make_tuple<string, string, string, string, int, std::function<void(const CommandLine&, MYSQL*, int, bool)>>("LOAD DATA LOCAL INFILE", "mysql-enable_load_data_local_infile", "'true'", "'false'", 1047, test_verbose_error_load_data_local_infile),
};

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) return -1;

	diag("================================================================================");
	diag("TEST DESCRIPTION: ProxySQL Unsupported and Conditional Query Validation");
	diag("This test verifies that ProxySQL handles unsupported commands (like LOAD DATA LOCAL)");
	diag("correctly by returning error 1047, and that these commands can be enabled");
	diag("conditionally via global variables.");
	diag("");
	diag("Connection Context:");
	diag("  - Host: %s", cl.host);
	diag("  - Port: %d", cl.port);
	diag("  - Admin Port: %d", cl.admin_port);
	diag("================================================================================");

	plan(unsupported_queries.size() + 4 * queries_tests_info.size());

	diag("Phase 1: Testing naturally unsupported queries (Expecting 1047)");
	for (const auto& unsupported_query : unsupported_queries) {
		MYSQL* mysql = mysql_init(NULL);
		if (mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			string q = std::get<0>(unsupported_query);
			diag("  - Executing: %s", q.c_str());
			int query_err = mysql_query(mysql, q.c_str());
			int m_errno = mysql_errno(mysql);
			ok(query_err && (m_errno == std::get<1>(unsupported_query)), "Unsupported query failed as expected");
			mysql_close(mysql);
		}
	}

	diag("Phase 2: Testing conditionally-enabled queries via ProxySQL Admin");
	MYSQL* admin = mysql_init(NULL);
	if (mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		for (const auto& query_test_info : queries_tests_info) {
			MYSQL* mysql = mysql_init(NULL);
			if (mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
				diag("Scenario: Testing %s", std::get<0>(query_test_info).c_str());
				// 1. Enable
				if (enable_query(admin, query_test_info, true)) {
					// 2. Test Enabled (performs 1 ok)
					std::get<5>(query_test_info)(cl, mysql, 0, true);
				}
				// 3. Disable
				if (enable_query(admin, query_test_info, false)) {
					// 4. Test Disabled (performs 1 ok)
					std::get<5>(query_test_info)(cl, mysql, std::get<4>(query_test_info), false);
				}
				mysql_close(mysql);
			}
		}
		mysql_close(admin);
	}

	return exit_status();
}
