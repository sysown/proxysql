#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <iostream>
#include <fstream>

#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include "utils.h"

using namespace std;

int main(int argc, char** argv) {
	CommandLine cl;

	// Plan for 6 tests
	plan(6);

	// Get connections
	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		diag("Failed to initialize admin connection");
		return exit_status();
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}

	// Get the log file path
	const string log_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };

	// Test 1: MySQL TCP keepalive warning
	diag("Testing MySQL TCP keepalive warning when set to false");
	{
		fstream logfile {};
		int open_err = open_file_and_seek_end(log_path, logfile);
		if (open_err != EXIT_SUCCESS) {
			diag("Failed to open log file: %s", log_path.c_str());
			mysql_close(admin);
			return exit_status();
		}

		// Set MySQL TCP keepalive to false
		int query_err = mysql_query(admin, "SET mysql-use_tcp_keepalive='false'");
		ok(query_err == 0, "SET mysql-use_tcp_keepalive='false' should succeed");
		if (query_err != 0) {
			diag("Error setting mysql-use_tcp_keepalive: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}

		// Load MySQL variables to runtime to trigger warning
		query_err = mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		ok(query_err == 0, "LOAD MYSQL VARIABLES TO RUNTIME should succeed");
		if (query_err != 0) {
			diag("Error loading MySQL variables: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}

		// Wait a bit for the warning to be written to log
		usleep(200000); // 200ms

		// Check for the warning in the log - scan only last 50 lines
	const string warning_regex { ".*\\[WARNING\\].*mysql-use_tcp_keepalive is set to false.*" };
	const auto& [match_count, warning_lines] = get_matching_lines(logfile, warning_regex, false, 50);

	// Scanning only last 50 lines ensures we're looking at recent log entries
	ok(match_count > 0, "MySQL TCP keepalive warning should appear in log when set to false");
		if (match_count == 0) {
			diag("Expected MySQL TCP keepalive warning not found in last 50 lines of log");
		} else {
			diag("Found %zu MySQL TCP keepalive warning(s) in last 50 lines", match_count);
		}
	}

	// Test 2: PostgreSQL TCP keepalive warning
	diag("Testing PostgreSQL TCP keepalive warning when set to false");
	{
		fstream logfile {};
		int open_err = open_file_and_seek_end(log_path, logfile);
		if (open_err != EXIT_SUCCESS) {
			diag("Failed to open log file: %s", log_path.c_str());
			mysql_close(admin);
			return exit_status();
		}

		// Set PostgreSQL TCP keepalive to false
		int query_err = mysql_query(admin, "SET pgsql-use_tcp_keepalive='false'");
		ok(query_err == 0, "SET pgsql-use_tcp_keepalive='false' should succeed");
		if (query_err != 0) {
			diag("Error setting pgsql-use_tcp_keepalive: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}

		// Load PgSQL variables to runtime to trigger warning
		query_err = mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		ok(query_err == 0, "LOAD PGSQL VARIABLES TO RUNTIME should succeed");
		if (query_err != 0) {
			diag("Error loading PgSQL variables: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}

		// Wait a bit for the warning to be written to log
		usleep(200000); // 200ms

		// Check for the warning in the log - scan only last 50 lines
		const string warning_regex { ".*\\[WARNING\\].*pgsql-use_tcp_keepalive is set to false.*" };
		const auto& [match_count, warning_lines] = get_matching_lines(logfile, warning_regex, false, 50);

		// Scanning only last 50 lines ensures we're looking at recent log entries
		ok(match_count > 0, "PostgreSQL TCP keepalive warning should appear in log when set to false");
		if (match_count == 0) {
			diag("Expected PostgreSQL TCP keepalive warning not found in last 50 lines of log");
		} else {
			diag("Found %zu PostgreSQL TCP keepalive warning(s) in last 50 lines", match_count);
		}
	}

	mysql_close(admin);
	return exit_status();
}