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

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Plan for 6 tests
	plan(6);

	// Check if REGULAR_INFRA_DATADIR is set, this is required for the test to work
	const char* infra_datadir_env = getenv("REGULAR_INFRA_DATADIR");
	if (infra_datadir_env == nullptr || strlen(infra_datadir_env) == 0) {
		diag("ERROR: REGULAR_INFRA_DATADIR environment variable is not set");
		diag("This test requires REGULAR_INFRA_DATADIR to be set to the ProxySQL data directory");
		diag("In isolated environment, this should be set to /var/lib/proxysql");
		return exit_status();
	}

	// Get the log file path
	const string log_path { string(infra_datadir_env) + "/proxysql.log" };
	diag("=== Regression Test #5212: TCP Keepalive Warnings ===");
	diag("PURPOSE:");
	diag("  This test verifies that ProxySQL logs warnings when TCP keepalive");
	diag("  is disabled (mysql-use_tcp_keepalive and pgsql-use_tcp_keepalive).");
	diag("TEST SCENARIOS:");
	diag("  - Set mysql-use_tcp_keepalive='false' and load to runtime");
	diag("  - Verify warning appears in ProxySQL log");
	diag("  - Set pgsql-use_tcp_keepalive='false' and load to runtime");
	diag("  - Verify warning appears in ProxySQL log");
	diag("ENVIRONMENT:");
	diag("  REGULAR_INFRA_DATADIR: %s", infra_datadir_env);
	diag("  Log file path: %s", log_path.c_str());
	diag("=========================================================================");

	// Get connections
	MYSQL* admin = mysql_init(NULL);
	if (!admin) {
		diag("Failed to initialize MySQL admin connection");
		return exit_status();
	}
	diag("Connecting to ProxySQL Admin at %s:%d as %s", cl.admin_host, cl.admin_port, cl.admin_username);

	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		mysql_close(admin);
		return exit_status();
	}
	diag("Successfully connected to ProxySQL Admin");

	// Test 1: MySQL TCP keepalive warning
	diag("=== Test 1: MySQL TCP keepalive warning ===");
	{
		// Check current value first
		string current_val = "";
		int query_err = mysql_query(admin, "SELECT @@mysql-use_tcp_keepalive");
		if (query_err != 0) {
			diag("Failed to query current mysql-use_tcp_keepalive value: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		
		MYSQL_RES* result = mysql_store_result(admin);
		if (!result) {
			diag("Failed to get result for mysql-use_tcp_keepalive query: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row) {
			current_val = row[0];
		}
		mysql_free_result(result);
		diag("Current mysql-use_tcp_keepalive value: %s", current_val.c_str());

		// Set MySQL TCP keepalive to false
		query_err = mysql_query(admin, "SET mysql-use_tcp_keepalive='false'");
		if (query_err != 0) {
			diag("Error setting mysql-use_tcp_keepalive: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		ok(query_err == 0, "SET mysql-use_tcp_keepalive='false' should succeed");
		if (query_err != 0) {
			mysql_close(admin);
			return exit_status();
		}
		diag("Set mysql-use_tcp_keepalive='false' - query executed successfully");

		// Load MySQL variables to runtime to trigger warning
		query_err = mysql_query(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		if (query_err != 0) {
			diag("Error loading MySQL variables: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		ok(query_err == 0, "LOAD MYSQL VARIABLES TO RUNTIME should succeed");
		if (query_err != 0) {
			mysql_close(admin);
			return exit_status();
		}
		diag("LOAD MYSQL VARIABLES TO RUNTIME - query executed successfully");

		// Wait a bit for the warning to be written to log
		diag("Waiting 500ms for log entries to be written...");
		usleep(500000);

		// Check for the warning in the log - scan only last 20 lines using filename-based function
		const string warning_regex { ".*WARNING.*mysql-use_tcp_keepalive is set to false.*" };
		const auto& [match_count, warning_lines] = get_matching_lines_from_filename(log_path, warning_regex, true, 20);
		
		// Scanning only last 20 lines ensures we recent log entries
		ok(match_count > 0, "MySQL TCP keepalive warning should appear in log when set to false (Lines found: %zu)", match_count);
		if (match_count == 0) {
			diag("Expected MySQL TCP keepalive warning not found in last 20 lines of log");
			diag("Last 20 lines of log:");
			for (size_t i = 0; i < warning_lines.size(); i++) {
				const string& line = std::get<LINE>(warning_lines[i]);
				diag("  Line %zu: %s", i, line.c_str());
			}
		} else {
			diag("Found %zu matching lines in log", match_count);
			for (size_t i = 0; i < warning_lines.size() && i < 3; i++) {
				const string& line = std::get<LINE>(warning_lines[i]);
				diag("  Match %zu: %s", i, line.c_str());
			}
		}
	}

	// Test 2: PostgreSQL TCP keepalive warning
	diag("=== Test 2: PostgreSQL TCP keepalive warning ===");
	{
		// Check current value first
		string current_val = "";
		int query_err = mysql_query(admin, "SELECT @@pgsql-use_tcp_keepalive");
		if (query_err != 0) {
			diag("Failed to query current pgsql-use_tcp_keepalive value: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		
		MYSQL_RES* result = mysql_store_result(admin);
		if (!result) {
			diag("Failed to get result for pgsql-use_tcp_keepalive query: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		
		MYSQL_ROW row = mysql_fetch_row(result);
		if (row) {
			current_val = row[0];
		}
		mysql_free_result(result);
		diag("Current pgsql-use_tcp_keepalive value: %s", current_val.c_str());

		// Set PostgreSQL TCP keepalive to false
		query_err = mysql_query(admin, "SET pgsql-use_tcp_keepalive='false'");
		if (query_err != 0) {
			diag("Error setting pgsql-use_tcp_keepalive: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		ok(query_err == 0, "SET pgsql-use_tcp_keepalive='false' should succeed");
		if (query_err != 0) {
			mysql_close(admin);
			return exit_status();
		}
		diag("Set pgsql-use_tcp_keepalive='false' - query executed successfully");

		// Load PgSQL variables to runtime to trigger warning
		query_err = mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
		if (query_err != 0) {
			diag("Error loading PgSQL variables: %s", mysql_error(admin));
			mysql_close(admin);
			return exit_status();
		}
		ok(query_err == 0, "LOAD PGSQL VARIABLES TO RUNTIME should succeed");
		if (query_err != 0) {
			mysql_close(admin);
			return exit_status();
		}
		diag("LOAD PGSQL VARIABLES TO RUNTIME - query executed successfully");

		// Wait a bit for the warning to be written to log
		diag("Waiting 500ms for log entries to be written...");
		usleep(500000);

		// Check for this warning in the log - scan only last 20 lines using filename-based function
		const string warning_regex { ".*WARNING.*pgsql-use_tcp_keepalive is set to false.*" };
		const auto& [match_count, warning_lines] = get_matching_lines_from_filename(log_path, warning_regex, true, 20);
        
		// Scanning only last 20 lines ensures we recent log entries
		ok(match_count > 0, "PostgreSQL TCP keepalive warning should appear in log when set to false (Lines found: %zu)", match_count);
		if (match_count == 0) {
			diag("Expected PostgreSQL TCP keepalive warning not found in last 20 lines of log");
			diag("Last 20 lines of log:");
			for (size_t i = 0; i < warning_lines.size(); i++) {
				const string& line = std::get<LINE>(warning_lines[i]);
				diag("  Line %zu: %s", i, line.c_str());
			}
		} else {
			diag("Found %zu matching lines in log", match_count);
			for (size_t i = 0; i < warning_lines.size() && i < 3; i++) {
				const string& line = std::get<LINE>(warning_lines[i]);
				diag("  Match %zu: %s", i, line.c_str());
			}
		}
	}

	diag("=== Test Summary ===");
	mysql_close(admin);
	return exit_status();
}
