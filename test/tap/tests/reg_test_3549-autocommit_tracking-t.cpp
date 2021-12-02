/**
 * @file reg_test_3549-autocommit_tracking-t.cpp
 * @brief This test verifies that ProxySQL is properly tracking autocommit being
 *   set, being properly forwarded to the client after changing its status.
 *
 *   TODO: This test should serve as the template from which construct a more
 *   complete test for 'autocommit' tracking, for client and backend sides.
 */

#include <cstring>
#include <vector>
#include <string>
#include <stdio.h>

#include <mysql.h>

#include "proxysql_utils.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

using query_spec = std::tuple<std::string, int>;

void fetch_and_discard_results(MYSQL_RES* result, bool verbose=false) {
	MYSQL_ROW row = nullptr;
	unsigned int num_fields = 0;
	unsigned int i = 0;
	unsigned int j = 0;

	num_fields = mysql_num_fields(result);
	while ((row = mysql_fetch_row(result))) {
		unsigned long *lengths = mysql_fetch_lengths(result);

		if (verbose) {
			printf("# RowNum_%d: ", j);
		}

		for(i = 0; i < num_fields; i++) {
			if (verbose) {
				printf("[%.*s] ", (int) lengths[i], row[i] ? row[i] : "NULL");
			}
		}

		if (verbose) {
			printf("\n");
		}

		j++;
	}
}

/**
 * @brief Execute the supplied queries and fetch and ignore the data in case of
 *   being necessary.
 *
 * @param proxysql An already opened MYSQL connection to ProxySQL.
 *
 * @param queries The query to be executed.
 */
int execute_and_fetch_query(MYSQL* proxysql, const std::string& query) {
	int query_err = mysql_query(proxysql, query.c_str());
	if (query_err == EXIT_SUCCESS) {
		MYSQL_RES* result = mysql_store_result(proxysql);
		if (result) {
			fetch_and_discard_results(result, false);
			mysql_free_result(result);
		}
	}

	return query_err;
}

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

bool check_client_autocommit(MYSQL* proxysql) {
	if (proxysql == NULL) return false;
	return proxysql->server_status & SERVER_STATUS_AUTOCOMMIT;
}

using test_spec = std::vector<std::pair<std::string, int>>;

/**
 * @brief Executes the provided queries specs, and logs if an error is found with
 *   the query execution, or the value expected after the query doesn't match.
 *
 * @param proxysql An already opened MYSQL connection to ProxySQL.
 * @param queries_specs The queries specs to execute and check.
 *
 * @return 'EXIT_SUCCESS' if all the queries were properly executed,
 *   'EXIT_FAILURE' otherwise.
 */
int execute_queries_specs(MYSQL* proxysql, const test_spec& queries_specs) {
	for (const auto& query_spec : queries_specs) {
		std::string query = std::get<0>(query_spec);
		int exp_autocommit = std::get<1>(query_spec);

		int myerr = execute_and_fetch_query(proxysql, query);
		if (myerr != EXIT_SUCCESS) {
			diag(
				"Query failed to be executed:"
				" (query: '%s', exp_err: '%d', act_err: '%d', err_msg: '%s', line: '%d')",
				query.c_str(), EXIT_SUCCESS, mysql_errno(proxysql), mysql_error(proxysql), __LINE__
			);
			return EXIT_FAILURE;
		} else {
			bool autocommit = check_client_autocommit(proxysql);
			if (autocommit != exp_autocommit) {
				diag(
					"Unexpected autocommit value for:"
					" (query: '%s', exp_autocommit: '%d', autocommit: '%d', line: '%d')",
					query.c_str(), exp_autocommit, autocommit, __LINE__
				);
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

/**
 * @brief The tests definition.
 */
std::vector<std::pair<std::string, test_spec>> test_definitions {
	{
		// Check if autocommit is properly set by using simple queries,
		// target to be handled by 'handler_special_queries' in ProxySQL side.
		"simple_set_autocommit_no_lock",
		{
			{ "SET autocommit=1",             1 },
			{ "SELECT /* ;hostgroup=0 */ 1",  1 },
			{ "SET autocommit=0",             0 },
			{ "SELECT /* ;hostgroup=0 */ 1",  0 }
		}
	},
	{
		"simple_set_autocommit_no_lock_2",
		{
			{ "SET autocommit=0",             0 },
			{ "SELECT /* ;hostgroup=0 */ 1",  0 },
			{ "COMMIT",                       0 },
			{ "SET autocommit=1",             1 },
			{ "SELECT /* ;hostgroup=0 */ 1", 1 }
		}
	},
	{
		"simple_set_autocommit_lock_1",
		{
			{ "SET @session_var=1",           1 },
			{ "SET autocommit=1",             1 },
			{ "SELECT /* ;hostgroup=0 */ 1",  1 },
			{ "SET autocommit=0",             0 },
			{ "SELECT /* ;hostgroup=0 */ 1",  0 }
		}
	},
	{
		"simple_set_autocommit_lock_2",
		{
			{ "SET @session_var=1",           1 },
			{ "SET autocommit=0",             0 },
			{ "SELECT /* ;hostgroup=0 */ 1",  0 },
			{ "COMMIT",                       0 },
			{ "SET autocommit=1",             1 },
			{ "SELECT /* ;hostgroup=0 */ 1",  1 }
		}
	},
	{
		// Check if autocommit is properly set by using complex queries,
		// target to be handled by 'handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo'
		// in ProxySQL side.
		"complex_set_autocommit_no_lock_1",
		{
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=1", 1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=0", 0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 }
		}
	},
	{
		"complex_set_autocommit_no_lock_2",
		{
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=0", 0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 },
			{ "COMMIT",                                                                                   0 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=1", 1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 }
		}
	},
	{
		"complex_set_autocommit_lock_1",
		{
			{ "SET @session_var=1",                                                                       1 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=1", 1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=0", 0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 }
		}
	},
	{
		"complex_set_autocommit_lock_2",
		{
			{ "SET @session_var=1",                                                                       1 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=0", 0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 },
			{ "COMMIT",                                                                                   0 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=1", 1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 }
		}
	},
	{
		"mix_set_autocommit_1",
		{
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=0", 0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 },
			{ "COMMIT",                                                                                   0 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=1", 1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 },
			{ "SET autocommit=0",                                                                         0 },
			{ "COMMIT",                                                                                   0 },
			{ "SET autocommit=1",                                                                         1 },
			{ "BEGIN",                                                                                    1 },
			{ "SET @session_var=1",                                                                       1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 },
			{ "COMMIT",                                                                                   1 },
		}
	},
	{
		"mix_set_autocommit_2",
		{
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=0", 0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 },
			{ "COMMIT",                                                                                   0 },
			{ "SET time_zone='+04:00', character_set_client='latin1', max_join_size=10000, autocommit=1", 1 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              1 },
			{ "SET autocommit=0",                                                                         0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 },
			{ "COMMIT",                                                                                   0 },
			{ "BEGIN",                                                                                    0 },
			{ "SET @session_var=1",                                                                       0 },
			{ "SELECT /* ;hostgroup=0 */ 1",                                                              0 },
			{ "COMMIT",                                                                                   0 },
		}
	},
};

/**
 * @brief Execute the supplied test definition on the provided, already oppened
 *   MySQL connection to ProxySQL.
 *
 * @param proxysql An already oppened connection to ProxySQL.
 * @param test_def The test definition to be verified.
 */
void execute_test_definition(MYSQL* proxysql, std::pair<std::string, test_spec> test_def) {
	int queries_res = execute_queries_specs(proxysql, test_def.second);
	std::string t_ok_msg {
		"Autocommit should match expected values for '%s' queries"
	};
	std::string ok_msg {};
	string_format(t_ok_msg, ok_msg, test_def.first.c_str());

	ok(
		queries_res == EXIT_SUCCESS,
		"%s", ok_msg.c_str()
	);
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	for (const auto& test_def : test_definitions) {
		MYSQL* proxysql_mysql = mysql_init(NULL);
		if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
			fprintf(
				stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql)
			);
			return EXIT_FAILURE;
		}

		// perform the next test
		execute_test_definition(proxysql_mysql, test_def);

		mysql_close(proxysql_mysql);
	}

	return exit_status();
}
