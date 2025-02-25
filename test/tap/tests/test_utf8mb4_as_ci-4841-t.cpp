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

	std::string var_collation_connection = "collation_connection";
	std::string var_value;

	show_variable(mysql, var_collation_connection, var_value, true);
	ok(var_value.compare("utf8mb4_0900_as_ci") == 0, "collation_connection , Expected utf8mb4_0900_as_ci . Actual %s", var_value.c_str()); // ok_1

	mysql_close(mysql);

	return exit_status();
}

