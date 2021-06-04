/**
 * @file test_unsupported_queries-t.cpp
 * @brief Simple test to check that unsupported queries by ProxySQL return the expected error codes.
 */

#include <cstring>
#include <vector>
#include <tuple>
#include <string>
#include <stdio.h>

#include <mysql.h>
#include <mysql/mysqld_error.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"

/**
 * @brief List of the pairs holding the unsupported queries to be executed by ProxySQL
 *   together with the error code that they should return.
 */
std::vector<std::tuple<std::string, int, std::string>> unsupported_queries {
	std::make_tuple<std::string, int, std::string>("LOAD DATA LOCAL INFILE", 1047, "Unsupported 'LOAD DATA LOCAL INFILE' command"),
	std::make_tuple<std::string, int, std::string>("LOAD DATA LOCAL INFILE 'data.txt' INTO TABLE db.test_table", 1047, "Unsupported 'LOAD DATA LOCAL INFILE' command"),
	std::make_tuple<std::string, int, std::string>("LOAD DATA LOCAL INFILE '/tmp/test.txt' INTO TABLE test IGNORE 1 LINES", 1047, "Unsupported 'LOAD DATA LOCAL INFILE' command"),
};

int main(int argc, char** argv) {
	CommandLine cl;

	// plan as many tests as queries
	plan(unsupported_queries.size());

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
			return -1;
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

	return exit_status();
}
