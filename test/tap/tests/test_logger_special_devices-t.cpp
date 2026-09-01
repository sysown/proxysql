/**
 * @file test_logger_special_devices-t.cpp
 * @brief Tests for MySQL_Logger special device file handling (/dev/stdout, /dev/stderr)
 * @details This test ensures that eventslog_filename and auditlog_filename can be set to
 *          special device files like /dev/stdout and /dev/stderr without rotation errors.
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <string>
#include <fstream>

#include "mysql.h"
#include "mysqld_error.h"
#include "proxysql.h"
#include "cpp-dotenv/dotenv.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	MYSQL* proxysql_admin = mysql_init(NULL);
	
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	plan(6);

	// Test 1: Set eventslog_filename to /dev/stdout (should not fail)
	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename='/dev/stdout'");
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(true, "Successfully set eventslog_filename to /dev/stdout");
	}

	// Test 2: Set eventslog_filename to /dev/stderr (should not fail)
	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename='/dev/stderr'");
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(true, "Successfully set eventslog_filename to /dev/stderr");
	}

	// Test 3: Set auditlog_filename to /dev/stdout (should not fail)
	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-auditlog_filename='/dev/stdout'");
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(true, "Successfully set auditlog_filename to /dev/stdout");
	}

	// Test 4: Set auditlog_filename to /dev/stderr (should not fail)
	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-auditlog_filename='/dev/stderr'");
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(true, "Successfully set auditlog_filename to /dev/stderr");
	}

	// Test 5: FLUSH LOGS with special device should work
	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename='/dev/stdout'");
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY(proxysql_admin, "PROXYSQL FLUSH LOGS");
		ok(true, "FLUSH LOGS works with /dev/stdout");
	}

	// Test 6: Verify we can switch back to regular file
	{
		MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename='/tmp/test_events.log'");
		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(true, "Successfully switched back to regular file");
	}

	// Cleanup
	MYSQL_QUERY(proxysql_admin, "SET mysql-eventslog_filename=''");
	MYSQL_QUERY(proxysql_admin, "SET mysql-auditlog_filename=''");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	mysql_close(proxysql_admin);

	return exit_status();
}