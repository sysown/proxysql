/**
 * @file test_set_stmt_status_variables-t.cpp
 * @brief This test verifies that backend_set_stmt, frontend_set_stmt and
 * frontend_failed_set_stmt behaves properly.
 *
 * @details It sends several SET statements to test that backend_set_stmt, frontend_set_stmt and
 * frontend_failed_set_stmt status variables are increased correctly.
 */

#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include <string>

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(3);

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("Sending SET statements");
	const std::vector<std::string> queries = {
		// Increase once Com_frontend_set_stmt
		"SET SQL_MODE='ALLOW_INVALID_DATES'",
		// Increase once Com_frontend_set_stmt
		"SET SQL_MODE='NO_ENGINE_SUBSTITUTION'",
		// SET NAMES should not increase any counter
		"SET NAMES latin1",
		// Increase once Com_frontend_set_stmt
		"SET TIME_ZONE='+01:00' SQL_SELECT_LIMIT=10000000",
	};
	for (std::string query : queries) {
		MYSQL_QUERY(proxy, query.c_str());
	}

	// Increase once Com_frontend_set_stmt and Com_frontend_failed_set_stmt
	const std::string wrong_set_stmt = "SET FOO='BAR'";
	int err = mysql_query(proxy, wrong_set_stmt.c_str());
	if (err != 1) {
		fprintf(stderr, "File %s, line %d, Error: %d - %s\n", __FILE__, __LINE__, err, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	// Increase by three Com_backend_set_stmt, beacuse we setted SQL_MODE, TIME_ZONE and SQL_SELECT_LIMIT
	const std::string dummy_query = "DO 1";
	MYSQL_QUERY(proxy, dummy_query.c_str());
	mysql_free_result(mysql_store_result(proxy));

	mysql_close(proxy);

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	int backend_set_stmt = 0;
	int frontend_set_stmt = 0;
	int frontend_failed_set_stmt = 0;
	std::string query =
		"SELECT * FROM stats_mysql_global "
		"WHERE variable_name IN ('Com_backend_set_stmt','Com_frontend_set_stmt', 'Com_frontend_failed_set_stmt')";
	MYSQL_QUERY(admin, query.c_str());
	MYSQL_RES *result = mysql_store_result(admin);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result)))
	{
		if (strcmp(row[0], "Com_backend_set_stmt") == 0) {
			backend_set_stmt = atoi(row[1]);
		} else if (strcmp(row[0], "Com_frontend_set_stmt") == 0) {
			frontend_set_stmt = atoi(row[1]);
		} else if (strcmp(row[0], "Com_frontend_failed_set_stmt") == 0) {
			frontend_failed_set_stmt = atoi(row[1]);
		} else {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, "unexpected status variable");
			return EXIT_FAILURE;
		}
	}

	mysql_free_result(result);
	mysql_close(admin);

	int expected_backend_set_stmt = 3;
	int expected_frontend_set_stmt = 3;
	int expected_frontend_failed_set_stmt = 1;
	ok(
		expected_backend_set_stmt == backend_set_stmt,
		"SET statements sent by ProxySQL. Expected: %d Actual: %d.",
		expected_backend_set_stmt, backend_set_stmt
	);
	ok(
		expected_frontend_set_stmt == frontend_set_stmt,
		"SET statements received by ProxySQL. Expected: %d Actual: %d.",
		expected_frontend_set_stmt, frontend_set_stmt
	);
	ok(
		expected_frontend_failed_set_stmt == frontend_failed_set_stmt,
		"SET statements failed to parse. Expected: %d Actual: %d.",
		expected_frontend_failed_set_stmt, frontend_failed_set_stmt
	);

	return exit_status();
}
