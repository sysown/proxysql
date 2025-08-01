/**
 * @file mysql-set_wait_timeout-t.cpp
 * @brief This TAP test validates if session 'wait_timeout' is working correctly.
 */

#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

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

int test_session_timeout(CommandLine *cl, MYSQL *admin) {
	diag("Test: %s", __func__);

	MYSQL_QUERY_T(admin, "SET mysql-wait_timeout=50000");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL* proxy = init_mysql_conn(cl->host, cl->username, cl->password, cl->port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(proxy, "SET wait_timeout=10");

	int rc = run_q(proxy, "DO 1");
	ok(rc == 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	sleep(12);

	rc = run_q(proxy, "DO 1");
	ok(rc != 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	mysql_close(proxy);
	return EXIT_SUCCESS;
}


int test_session_timeout_exceed_global_timeout(CommandLine *cl, MYSQL *admin) {
	diag("Test: %s", __func__);

	MYSQL_QUERY_T(admin, "SET mysql-wait_timeout=10000");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL*proxy = init_mysql_conn(cl->host, cl->username, cl->password, cl->port);
	if (!proxy) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	MYSQL_QUERY_T(proxy, "SET wait_timeout=20");

	int rc = run_q(proxy, "DO 1");
	ok(rc == 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	sleep(12);

	rc = run_q(proxy, "DO 1");
	ok(rc != 0, (rc == 0 ? "Connection alive" : "Connection killed"));

	mysql_close(proxy);
	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	plan(4);

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

	int rc = test_session_timeout(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	rc = test_session_timeout_exceed_global_timeout(&cl, admin);
	if (rc != EXIT_SUCCESS) {
		return exit_status();
	}

	mysql_close(admin);
	return exit_status();
}
