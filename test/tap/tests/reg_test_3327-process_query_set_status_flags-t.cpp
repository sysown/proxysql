/**
 * @file reg_test_3327-process_query_set_status_flags-t.cpp
 * @brief This test is a regression test for issue #3327.
 * @details The test performs a invalid query that according to the new introduced behavior in
 *   ProxySQL #3327 should be processed by 'ProcessQueryAndSetStatusFlags' and disable multiplexing.
 * @date 2021-03-01
 */

#include <vector>
#include <string>
#include <stdio.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"

using std::string;
using namespace nlohmann;

CommandLine cl;

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int main(int argc, char** argv) {

	MYSQL* proxysql_mysql = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return -1;
	}

	int query_err = mysql_query(proxysql_mysql, "SELECT SQL_CALC_FOUND_ROWS * FROM reg_test_3327_non_exist_table");
	ok (query_err != 0, "Initial query failed as intended.");

	MYSQL_QUERY(proxysql_mysql, "PROXYSQL INTERNAL SESSION");
	json j_status {};
	MYSQL_RES* int_session_res = mysql_store_result(proxysql_mysql);
	parse_result_json_column(int_session_res, j_status);
	mysql_free_result(int_session_res);

	if (j_status.contains("backends")) {
		bool found_backend = false;
		for (auto& backend : j_status["backends"]) {
			if (backend != nullptr && backend.contains("conn") && backend["conn"].contains("status")) {
				found_backend = true;
				bool multiplex_disabled = backend["conn"]["MultiplexDisabled"];
				ok(
					multiplex_disabled == true,
					"Connection status should reflect that 'MultiplexDisabled' is enabled due to the invalid 'SELECT SQL_CALC_FOUND_ROWS'."
				);
			}
		}
		if (found_backend == false) {
			ok(false, "'backends' doens't contains 'conn' objects with the relevant session information");
		}
	} else {
		ok(false, "No backends detected for the current connection.");
	}

	mysql_close(proxysql_mysql);

	return exit_status();
}
