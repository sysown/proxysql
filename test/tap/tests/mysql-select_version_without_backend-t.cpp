/**
 * @file mysql-select_version_without_backend-t.cpp
 * @brief This TAP test validates if SELECT VERSION() works without making calls to the backend.
 */

#include <unistd.h>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

using std::string;

#define MYSQL_TEST_SERVER_VERSION "8.4.6"
#define MYSQL_SET_SERVER_VERSION_QUERY "SET mysql-server_version='" MYSQL_TEST_SERVER_VERSION "'"

MYSQL* init_mysql_conn(char* host, char* user, char* pass, int port) {
	diag("Creating MySQL conn host=\"%s\" port=\"%d\" user=\"%s\"", host, port, user);

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) {
		return nullptr;
	}

	if (!mysql_real_connect(mysql, host, user, pass, NULL, port, NULL, 0)) {
		return nullptr;
	}

	return mysql;
}

int run_q(MYSQL *mysql, const char *q) {
	MYSQL_QUERY_T(mysql,q);
	return 0;
}

int main(int argc, char** argv) {
	plan(2);

	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return exit_status();
	}

	MYSQL* admin = init_mysql_conn(cl.host, cl.admin_username, cl.admin_password, cl.admin_port);
	if (!admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return exit_status();
	}

	MYSQL_QUERY_T(admin, MYSQL_SET_SERVER_VERSION_QUERY);
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_servers");
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl.host, cl.username, cl.password, cl.port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return exit_status();
	}

	const char *version_get_queries[2] = {
		"SELECT @@VERSION",
		"SELECT VERSION()"
	};

	for (int i = 0; i < 2; i++) {
		MYSQL_ROW row = nullptr;
		string res_server_version;

		int rc = run_q(proxy, version_get_queries[i]);
		if (rc == 0) {
			MYSQL_RES* proxy_res = mysql_store_result(proxy);

			row = mysql_fetch_row(proxy_res);
			if (row) {
				res_server_version = row[0];
			}

			mysql_free_result(proxy_res);
		}

		ok(row && (res_server_version == MYSQL_TEST_SERVER_VERSION), "Server version: %s", res_server_version.c_str());
	}

	mysql_close(admin);
	mysql_close(proxy);

	return exit_status();
}
