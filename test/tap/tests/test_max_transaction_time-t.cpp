/**
 * @file test_max_transaction_time-t.cpp
 * @brief This test verifies that 'max_transaction_time' behaves properly.
 *
 * @details It verifies that connection with many transactions does not get
 * killed by the max_transaction_time implementation if each individual
 * transaction takes shorter than max_transaction_time.
 */

#include "mysql.h"

#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

using std::string;

int main(int, char**) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	diag("Configure the target server (non-existing) server to test connection failures");
	MYSQL_QUERY_T(
		admin,
		"UPDATE global_variables SET variable_value = 10000 "
		"WHERE variable_name = 'mysql-max_transaction_time'"
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(admin);

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	diag("Run fifteen 1-second transactions:");
	MYSQL_RES* myres;
	for (int i = 0; i < 15; i++) {
		MYSQL_QUERY_T(proxy, "BEGIN");

		MYSQL_QUERY_T(proxy, "SELECT SLEEP(1)");
		myres = mysql_store_result(proxy);
		if (myres == nullptr) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}
		mysql_free_result(myres);

		MYSQL_QUERY_T(proxy, "COMMIT");
	}

	mysql_close(proxy);

	return exit_status();
}
