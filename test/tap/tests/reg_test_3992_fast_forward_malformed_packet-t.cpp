/**
 * @file reg_test_3992-fast_forward_malformed_packet-t.cpp
 * @brief This is a regression test for issue #3992. Test checks if queries are executed successfully with MariaDB  
 *  server having fast forward flag set to true and false.
 * @details The test executes basic queries to check execution in MariaDB with Fast Forward flags on/off
 *   
 */

#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Verbose test header
	diag("================================================================================");
	diag("Test: reg_test_3992_fast_forward_malformed_packet-t");
	diag("================================================================================");
	diag("This test verifies that ProxySQL correctly handles MariaDB connections when");
	diag("Fast Forward is enabled. Specifically, it checks for potential malformed");
	diag("packets during the handshake/authentication phase when forwarding queries.");
	diag("It tests with two users:");
	diag("  - mariadbuserff: Expected to have Fast Forward ENABLED (hg 1000)");
	diag("  - mariadbuser:   Expected to have Fast Forward DISABLED (hg 1001)");
	diag(" ");
	diag("Connection parameters:");
	diag("  - ProxySQL Host: %s", cl.host);
	diag("  - ProxySQL Port: %d", cl.port);
	diag("  - ProxySQL Admin Port: %d", cl.admin_port);
	diag("  - Workdir: %s", cl.workdir);
	diag("================================================================================");
	diag(" ");

	// Debugging: Dump initial ProxySQL state
	MYSQL* admin = mysql_init(NULL);
	diag("Attempting connection to ProxySQL Admin at %s:%d...", cl.host, cl.admin_port);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		diag("CRITICAL: Could not connect to ProxySQL Admin. Test cannot proceed.");
		return EXIT_FAILURE;
	}
	diag("Connected to ProxySQL Admin.");

	diag("Dumping relevant configuration from ProxySQL Admin:");
	
	diag("--- mysql_servers ---");
	if (mysql_query(admin, "SELECT hostgroup_id, hostname, port, status FROM mysql_servers") == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		if (res) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				diag("  hg=%s, host=%s, port=%s, status=%s", row[0], row[1], row[2], row[3]);
			}
			mysql_free_result(res);
		}
	}

	diag("--- mysql_users ---");
	if (mysql_query(admin, "SELECT username, default_hostgroup, transaction_persistent, fast_forward FROM mysql_users WHERE username LIKE 'mariadbuser%%'") == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		if (res) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				diag("  user=%s, hg=%s, persist=%s, ff=%s", row[0], row[1], row[2], row[3]);
			}
			mysql_free_result(res);
		} else {
			diag("  (No mariadbuser%% found in mysql_users)");
		}
	}

	diag("--- runtime_mysql_users ---");
	if (mysql_query(admin, "SELECT username, default_hostgroup, transaction_persistent, fast_forward FROM runtime_mysql_users WHERE username LIKE 'mariadbuser%%'") == 0) {
		MYSQL_RES* res = mysql_store_result(admin);
		if (res) {
			MYSQL_ROW row;
			while ((row = mysql_fetch_row(res))) {
				diag("  user=%s, hg=%s, persist=%s, ff=%s", row[0], row[1], row[2], row[3]);
			}
			mysql_free_result(res);
		} else {
			diag("  (No mariadbuser%% found in runtime_mysql_users)");
		}
	}

	mysql_close(admin);
	diag("Closed ProxySQL Admin connection.");
	diag(" ");

	std::vector<MYSQL*> conns;
	
	const std::vector<std::pair<std::string, std::string>> users { {"mariadbuserff", "mariadbuserff"},
											   {"mariadbuser", "mariadbuser"} };

	const std::vector<std::string> queries {"SHOW DATABASES", "SELECT 1"};

	plan(users.size() * queries.size());

	for (const auto& user : users)
	{
		diag("Attempting connection to ProxySQL as user '%s'...", user.first.c_str());
		MYSQL* mysql = mysql_init(NULL);
		
		if (!mysql) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return EXIT_FAILURE;
		}

		if (!mysql_real_connect(mysql, cl.host, user.first.c_str(), user.second.c_str(), NULL, cl.port, NULL, 0)) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			diag("Failed to connect as user '%s'.", user.first.c_str());
			return EXIT_FAILURE;
		}
		diag("Successfully connected as user '%s'.", user.first.c_str());

		conns.push_back(mysql);
	}

	int user_idx = 0;
	for (MYSQL* conn : conns)
	{
		const std::string& username = users[user_idx++].first;
		diag("Executing queries for user '%s':", username.c_str());
		for (const std::string& query : queries)
		{
			diag("  Query: '%s'", query.c_str());
			const int q_err = mysql_query(conn, query.c_str());

			if (q_err == EXIT_SUCCESS)
			{
				MYSQL_RES *result = mysql_store_result(conn);
				if (result) {
					mysql_free_result(result);
				}

				ok(true, "User '%s': Executing query '%s' should succeed", username.c_str(), query.c_str());
			}
			else {
				diag("  Query failed: %s", mysql_error(conn));
				ok(false, "User '%s': Executing query '%s' should succeed", username.c_str(), query.c_str());
			}
		}
		
		mysql_close(conn);
	}

	return exit_status();
}
