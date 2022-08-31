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

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "command_line.h"
#include "json.hpp"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

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

// "SET mysql-enable_load_data_local_infile='true'",

/**
 * @brief Enable the query based using the information supplied in the
 *   'query_info' parameter, and verifies that the value of the query has properly
 *   change at runtime.
 *
 * @param proxysql_admin An already oppened connection to ProxySQL Admin.
 * @param query_info Information about the query to be enabled.
 *
 * @return True if the query was properly enabled, false if not.
 */
bool enable_query(MYSQL* proxysql_admin, const query_test_info& query_info, bool enable=true) {
	std::string exp_var_value {};

	// In case of false, we choose the value for disabling the variable
	if (enable == true) {
		exp_var_value =  std::get<2>(query_info);
	} else {
		exp_var_value =  std::get<3>(query_info);
	}

	std::vector<std::string> enabling_queries {
		"SET " + std::get<1>(query_info) + " = " + exp_var_value,
		"LOAD MYSQL VARIABLES TO RUNTIME"
	};

	bool query_enabling_succeed = true;

	for (const auto& query : enabling_queries) {
		int query_res = mysql_query(proxysql_admin, query.c_str());
		if (query_res) {
			diag(
				"Query '%s' for enabling query '%s' enabling at line '%d', with error: '%s'",
				query.c_str(), std::get<0>(query_info).c_str(), __LINE__,
				mysql_error(proxysql_admin)
			);
			query_enabling_succeed = false;
			goto exit;
		}
	}

	{
		std::string variable_value {};
		int var_err = get_variable_value(
			proxysql_admin, std::get<1>(query_info), variable_value, true
		);

		if (var_err) {
			diag(
				"Getting value for variable '%s', failed with error: '%d'",
				std::get<1>(query_info).c_str(), var_err
			);
			query_enabling_succeed = false;
			goto exit;
		}

		// perform a final conversion in case it's required for the exp value
		std::string f_exp_var_value {};
		if (exp_var_value == "'true'") {
			f_exp_var_value = "true";
		} else if (exp_var_value == "'false'") {
			f_exp_var_value = "false";
		} else {
			f_exp_var_value = exp_var_value;
		}

		if (variable_value != f_exp_var_value) {
			query_enabling_succeed = false;
			diag(
				"Variable value doesn't match expected: (Exp: '%s', Act: '%s')",
				exp_var_value.c_str(), variable_value.c_str()
			);
			goto exit;
		}
	}

exit:

	return query_enabling_succeed;
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
 *
 * @param cl CommandLine parameters required for the test.
 * @param proxysql An already oppened connection to ProxySQL.
 * @param exp_err The expected error code in case we are testing for failure,
 *   '0' by default.
 * @param test_for_success Select the operation mode of the test, 'true' for
 *   testing for success, 'false' for failure. It's 'true' by default.
 */
void helper_test_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	std::string datafile {
		std::string { cl.workdir } + "load_data_local_datadir/insert_data.txt"
	};

	bool table_prep_success = true;

	for (const auto& query : prepare_table_queries) {
		int query_res = mysql_query(proxysql, query.c_str());
		if (query_res) {
			diag(
				"Query '%s' for table preparation failed at line '%d', with error: '%s'",
				query.c_str(), __LINE__, mysql_error(proxysql)
			);
			table_prep_success = false;
			break;
		}
	}

	if (table_prep_success) {
		std::string t_load_data_command {
			"LOAD DATA LOCAL INFILE \"%s\" INTO TABLE test.load_data_local"
				" FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\\n'"
		};
		std::string load_data_command {};
		string_format(t_load_data_command, load_data_command, datafile.c_str());

		int load_data_res =
			mysql_query(proxysql, load_data_command.c_str());

		if (test_for_success) {
			if (load_data_res) {
				diag(
					load_data_command.c_str(), __LINE__, mysql_error(proxysql)
				);
			}

			if (load_data_res == EXIT_SUCCESS) {
				diag(
					"Supplied query '%s' succeeded, performing check on data...",
					load_data_command.c_str()
				);
			} else {
				diag(
					"Supplied query '%s' failed, check not going to be performed. Error was: '%s'.",
					load_data_command.c_str(), mysql_error(proxysql)
				);
			}

			// Check that the data has actually been loaded to the database
			// NOTE: Specifically target 'hostgroup=0' to avoid replication lag.
			int myerr = mysql_query(proxysql, "SELECT * /* ;hostgroup=0 */ FROM test.load_data_local");
			if (myerr) {
				diag(
					"Query 'SELECT * FROM test.load_data_local' for table preparation failed"
					" at line '%d', with error: '%s'", __LINE__, mysql_error(proxysql)
				);
			} else {
				MYSQL_RES* result = mysql_store_result(proxysql);
				std::vector<mysql_res_row> rows_res { extract_mysql_rows(result) };
				std::vector<mysql_res_row> exp_rows {
					{ "1","a string","100.20" },
					{ "2","a string containing a , comma","102.20" },
					{ "3","a string containing a \" quote","102.20" },
					{ "4","a string containing a \", quote and comma","102.20" }
				};

				std::string exp_rows_str { "{\n" };
				for (const auto& exp_row : exp_rows) {
					std::string exp_row_str { nlohmann::json(exp_row).dump() };
					exp_rows_str += "    " + exp_row_str + ",\n";
				}
				exp_rows_str += "}\n";

				diag("Expected values for rows were: \n%s", exp_rows_str.c_str());

				std::string act_rows_str { "{\n" };
				for (const auto& act_row : rows_res) {
					std::string act_row_str { nlohmann::json(act_row).dump() };
					act_rows_str += "    " + act_row_str + ",\n";
				}
				act_rows_str += "}\n";

				diag("Actual values for found rows were: \n%s", act_rows_str.c_str());

				bool equal = false;
				if (!rows_res.empty()) {
					equal = std::equal(exp_rows.begin(), exp_rows.end(), rows_res.begin());
				}

				ok(equal, "The selected ROWS were equal to the expected ones");
			}
		} else {
			if (load_data_res) {
				diag(
					load_data_command.c_str(), __LINE__, mysql_error(proxysql)
				);
			}

			int my_errno = mysql_errno(proxysql);
			ok(
				my_errno == exp_err,
				"Query '%s' should fail. ErrCode: '%d', and error: '%s'",
				load_data_command.c_str(), my_errno, mysql_error(proxysql)
			);
		}
	}
}

/**
 * @brief Perform the same test as 'test_load_data_local_infile', but with
 *   'mysql-verbose_query_error' set to 'true'. This test only purpose is
 *   to exercise the code performing the additional extra logging.
 */
void test_verbose_error_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0
		)
	) {
		diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return;
	}

	std::vector<std::string> verbose_query_error_true {
		"SET mysql-verbose_query_error='true'",
		"LOAD MYSQL VARIABLES TO RUNTIME"
	};
	for (const auto& query : verbose_query_error_true) {
		int query_err = mysql_query(proxysql_admin, query.c_str());
		if (query_err) {
			diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return;
		}
	}

	helper_test_load_data_local_infile(cl, proxysql, exp_err, test_for_success);

	std::vector<std::string> verbose_query_error_false {
		"SET mysql-verbose_query_error='false'",
		"LOAD MYSQL VARIABLES TO RUNTIME"
	};
	for (const auto& query : verbose_query_error_false) {
		int query_err = mysql_query(proxysql_admin, query.c_str());
		if (query_err) {
			diag("File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
			return;
		}
	}

	mysql_close(proxysql_admin);
}

/**
 * @brief Test that the query 'LOAD DATA LOCAL INFILE' performs correctly when
 *   enabled, and returns the proper error code when disabled. Performs one
 *   'ok()' call in case everything went as expected, and several 'diag()' call
 *   in case of errors.
 *
 * @param cl CommandLine parameters required for the test.
 * @param proxysql An already oppened connection to ProxySQL.
 * @param exp_err The expected error code in case we are testing for failure,
 *   '0' by default.
 * @param test_for_success Select the operation mode of the test, 'true' for
 *   testing for success, 'false' for failure. It's 'true' by default.
 */
void test_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	helper_test_load_data_local_infile(cl, proxysql, exp_err, test_for_success);
}

/**
 * @brief Analogous function to 'test_load_data_local_infile' but it
 *   deliberately provides a non-existing file as an argument to make the query
 *   fail.
 *
 * @details This way we make sure that ProxySQL is exhibiting proper behavior
 *   for this unsupported query that can be misused.
 * @param cl CommandLine parameters required for the test.
 * @param proxysql An already oppened connection to ProxySQL.
 * @param exp_err The expected error code in case we are testing for failure,
 *   '0' by default.
 * @param test_for_success Select the operation mode of the test, 'true' for
 *   testing for success, 'false' for failure. It's 'true' by default.
 */
void test_failing_load_data_local_infile(
	const CommandLine& cl, MYSQL* proxysql, int exp_err=0, bool test_for_success=true
) {
	// Supply an invalid file
	std::string datafile {
		std::string { cl.workdir } + "load_data_local_datadir/non_existing_file.txt"
	};

	bool table_prep_success = true;

	for (const auto& query : prepare_table_queries) {
		int query_res = mysql_query(proxysql, query.c_str());
		if (query_res) {
			diag(
				"Query '%s' for table preparation failed at line '%d', with error: '%s'",
				query.c_str(), __LINE__, mysql_error(proxysql)
			);
			table_prep_success = false;
			break;
		}
	}

	if (table_prep_success) {
		std::string t_load_data_command {
			"LOAD DATA LOCAL INFILE \"%s\" INTO TABLE test.load_data_local"
		};
		std::string load_data_command {};
		string_format(t_load_data_command, load_data_command, datafile.c_str());

		int load_data_res =
			mysql_query(proxysql, load_data_command.c_str());

		if (test_for_success) {
			if (load_data_res) {
				diag(
					load_data_command.c_str(), __LINE__, mysql_error(proxysql)
				);
			}

			int my_errno = mysql_errno(proxysql);
			ok(
				(load_data_res != EXIT_SUCCESS) && my_errno == 2,
				"Query '%s' should fail. ErrCode: '%d', and error: '%s'",
				load_data_command.c_str(), mysql_errno(proxysql), mysql_error(proxysql)
			);
		} else {
			if (load_data_res) {
				diag(
					load_data_command.c_str(), __LINE__, mysql_error(proxysql)
				);
			}

			int my_errno = mysql_errno(proxysql);
			ok(
				my_errno == exp_err,
				"Query '%s' should fail. ErrCode: '%d', and error: '%s'",
				load_data_command.c_str(), my_errno, mysql_error(proxysql)
			);
		}
	}
}

// ****************************************************************** //


// ********************* QUERIES TESTS INFO  ************************ //

/**
 * @brief List of queries which need to be check before performing the
 *   'unsupported' checks.
 */
std::vector<query_test_info> queries_tests_info {
	std::make_tuple<
		std::string, std::string, std::string, std::string, int,
		std::function<void(const CommandLine&, MYSQL*, int, bool)>
	>(
		// Query to be tested
		"LOAD DATA LOCAL INFILE",
		// Variable name enabling / disabling the query
		"mysql-enable_load_data_local_infile",
		// Value for enabling the query
		"'true'",
		// Value for diabling the query
		"'false'",
		// Expected error code in case of failure
		1047,
		// Function performing an internal 'ok' test checking that the
		// enabled / disabled query responds as expected
		test_load_data_local_infile
	),
	std::make_tuple<
		std::string, std::string, std::string, std::string, int,
		std::function<void(const CommandLine&, MYSQL*, int, bool)>
	>(
		// Query to be tested
		"LOAD DATA LOCAL INFILE",
		// Variable name enabling / disabling the query
		"mysql-enable_load_data_local_infile",
		// Value for enabling the query
		"'true'",
		// Value for diabling the query
		"'false'",
		// Expected error code in case of failure
		1047,
		// Function performing an internal 'ok' test checking that the
		// enabled / disabled query responds as expected
		test_failing_load_data_local_infile
	),
	std::make_tuple<
		std::string, std::string, std::string, std::string, int,
		std::function<void(const CommandLine&, MYSQL*, int, bool)>
	>(
		// Query to be tested
		"LOAD DATA LOCAL INFILE",
		// Variable name enabling / disabling the query
		"mysql-enable_load_data_local_infile",
		// Value for enabling the query
		"'true'",
		// Value for diabling the query
		"'false'",
		// Expected error code in case of failure
		1047,
		// Function performing an internal 'ok' test checking that the
		// enabled / disabled query responds as expected
		test_verbose_error_load_data_local_infile
	),
};

// ****************************************************************** //

int main(int argc, char** argv) {
	CommandLine cl;

	// plan as many tests as queries
	plan(unsupported_queries.size() + 4 * queries_tests_info.size());

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// perform a different connection per query
	for (const auto& unsupported_query : unsupported_queries) {
		MYSQL* proxysql_mysql = mysql_init(NULL);

		// extract the tuple elements
		const std::string query = std::get<0>(unsupported_query);
		const int exp_err_code = std::get<1>(unsupported_query);
		const std::string exp_err_msg = std::get<2>(unsupported_query);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return EXIT_FAILURE;
		}

		int query_err = mysql_query(proxysql_mysql, query.c_str());
		int m_errno = mysql_errno(proxysql_mysql);
		const char* m_error = mysql_error(proxysql_mysql);

		ok(
			query_err && ( m_errno == exp_err_code ) && ( exp_err_msg == std::string { m_error } ),
			"Unsupported query '%s' should fail. Error code: (Expected: '%d' == Actual:'%d'), Error msg: (Expected: '%s' == Actual:'%s')",
			query.c_str(),
			exp_err_code,
			m_errno,
			exp_err_msg.c_str(),
			m_error
		);

		mysql_close(proxysql_mysql);
	}

	// Create required connection to ProxySQL admin required to perform the
	// tests for conditionally enabled queries.
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (
		!mysql_real_connect(
			proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0
		)
	) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

	// Enable and test the queries that can be conditionally enabled
	for (const auto& query_test_info : queries_tests_info) {
		MYSQL* proxysql_mysql = mysql_init(NULL);

		// extract the tuple elements
		const std::string query = std::get<0>(query_test_info);
		const std::string variable_name = std::get<1>(query_test_info);
		int exp_err = std::get<4>(query_test_info);
		const auto& testing_fn = std::get<5>(query_test_info);

		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			return EXIT_FAILURE;
		}

		bool query_enabling_succeed = enable_query(proxysql_admin, query_test_info, true);
		ok(
			query_enabling_succeed, "Enabling query '%s' should succeed.",
			std::get<0>(query_test_info).c_str()
		);

		// Check that the query is now properly supported
		testing_fn(cl, proxysql_mysql, 0, true);

		bool query_disabling_succeed = enable_query(proxysql_admin, query_test_info, false);
		ok(
			query_disabling_succeed, "Disabling query '%s' should succeed.",
			std::get<0>(query_test_info).c_str()
		);

		// Check that the query is now failing
		testing_fn(cl, proxysql_mysql, exp_err, false);

		mysql_close(proxysql_mysql);
	}

	mysql_close(proxysql_admin);

	return exit_status();
}
