#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

int main(int argc, char** argv) {
	std::vector<string> autocommit_queries = {
		"SELECT @@AUTOCOMMIT",
		"SELECT @@autocommit",
		"select @@AUTOCOMMIT",
		"select @@autocommit"
	};

	std::vector<std::pair<string, string>> autocommit_states = {
		{ "SET autocommit=0",     "0" },
		{ "SET autocommit=1",     "1" },
		{ "SET autocommit=OFF",   "0" },
		{ "SET autocommit=ON",    "1" },
		{ "SET autocommit=Off",   "0" },
		{ "SET autocommit=On",    "1" },
		{ "SET autocommit=false", "0" },
		{ "SET autocommit=true",  "1" },
		{ "SET autocommit=FaLSe", "0" },
		{ "SET autocommit=tRuE",  "1" },
	};

	int num_plans = autocommit_queries.size() + 1; // 1 for multiplex status check
	num_plans = autocommit_states.size() * num_plans;
	num_plans = num_plans + 2; // 2 for query_count checks

	plan(num_plans);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	MYSQL* mysql = init_mysql_conn(cl.host, cl.port, cl.username, cl.password);
	if (!mysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
		return exit_status();
	}

	// clear the conn pool stats
	MYSQL_QUERY_T(admin, "SELECT 1 FROM stats.stats_mysql_connection_pool_reset");
	MYSQL_RES* reset_result = mysql_store_result(admin);
	mysql_free_result(reset_result);

	// make this connection associated with a backend
	MYSQL_QUERY_T(mysql, "DO 1");

	check_query_count(admin, 1);

	// get multiplexing status before test
	bool multiplex_disabled = false;
	int rc = fetch_multiplex_disabled(mysql, multiplex_disabled);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	for (auto& s : autocommit_states) {
		auto set_cmd = s.first;
		auto expected = s.second;

		MYSQL_QUERY_T(mysql, set_cmd.c_str());

		for (auto& q : autocommit_queries) {
			MYSQL_ROW row = nullptr;
			string autocommit_val;

			int rc = run_q(mysql, q.c_str());
			if (rc == 0) {
				MYSQL_RES* result = mysql_store_result(mysql);

				row = mysql_fetch_row(result);
				if (row) {
					autocommit_val = row[0];
				}

				mysql_free_result(result);
			}

			ok(row && (autocommit_val == expected), "@@autocommit: %s", autocommit_val.c_str());
		}

		bool curr_multiplex_disabled = false;
		int rc = fetch_multiplex_disabled(mysql, curr_multiplex_disabled);
		if (rc != EXIT_SUCCESS) {
			return exit_status();
		}

		ok(curr_multiplex_disabled == multiplex_disabled, "MultiplexDisabled: %s", (curr_multiplex_disabled ? "true" : "false"));
	}

	check_query_count(admin, 1);

	mysql_close(mysql);
	mysql_close(admin);

	return exit_status();
}