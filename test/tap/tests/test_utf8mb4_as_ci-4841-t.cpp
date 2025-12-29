/**
 * @file test_utf8mb4_as_ci-4841-t.cpp
 * @brief This test checks the use of collation 305 (utf8mb4_as_ci) .
 * @details The test performs a 'SET NAMES' query to set utf8mb4_as_ci collation, then run a query
 * on backend to verify the collation.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

const int MYSQL8_HG = get_env_int("TAP_MYSQL8_BACKEND_HG", 30);

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(1);
	diag("Testing SET NAMES utf8mb4 COLLATE utf8mb4_0900_as_ci");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql)
		return exit_status();

	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n",
				mysql_error(mysql));
		return exit_status();
	}

	char * query = (char *)"SET NAMES utf8mb4 COLLATE utf8mb4_0900_as_ci";
	if (mysql_query(mysql, query)) {
		fprintf(stderr, "%s: Error: %s\n",
				query,
				mysql_error(mysql));
		return exit_status();
	}

	const string select_query {
		"SELECT /* hostgroup=" + _TO_S(MYSQL8_HG) + ";create_new_connection=1 */ @@collation_connection"
	};
	ext_val_t<string> var_ext { mysql_query_ext_val(mysql, select_query, string {}) };
	if (var_ext.err) {
		const string err { get_ext_val_err(mysql, var_ext) };
		diag("Failed query   query:`%s`, err:`%s`", select_query.c_str(), err.c_str());
		return EXIT_FAILURE;
	}

	ok(
		"utf8mb4_0900_as_ci" == var_ext.val,
		"collation_connection , Expected utf8mb4_0900_as_ci . Actual %s",
		var_ext.val.c_str()
	); // ok_1

	mysql_close(mysql);

	return exit_status();
}

