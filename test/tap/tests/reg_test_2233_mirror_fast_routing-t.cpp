/**
 * @file reg_test_2233_mirror_fast_routing-t.cpp
 * @brief Regression test for issue #2233: Mirror sessions incorrectly have their
 *        destination_hostgroup overwritten by fast routing rules.
 *
 * This test verifies that:
 * 1. Original queries are routed to the hostgroup specified by fast routing rules
 * 2. Mirror queries are routed to the mirror_hostgroup and NOT overwritten by fast routing
 *
 * ## Backend Configuration
 *
 * This test uses ProxySQL's SQLite3 Server as the backend (port 6030).
 * No external MySQL server is required.
 *
 *   # Start ProxySQL with SQLite3 server enabled
 *   proxysql --sqlite3-server
 *
 *   # Run the test
 *   ./reg_test_2233_mirror_fast_routing-t
 *
 * ## Environment Variables
 *
 * Standard TAP test variables (see command_line.cpp):
 *   - TAP_HOST: ProxySQL client host (default: 127.0.0.1)
 *   - TAP_PORT: ProxySQL client port (default: 6033)
 *   - TAP_USERNAME: ProxySQL client username
 *   - TAP_PASSWORD: ProxySQL client password
 *   - TAP_ADMINHOST: ProxySQL admin host (default: 127.0.0.1)
 *   - TAP_ADMINPORT: ProxySQL admin port (default: 6032)
 *   - TAP_ADMINUSERNAME: ProxySQL admin username
 *   - TAP_ADMINPASSWORD: ProxySQL admin password
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "MySQL_Session.h"
#include "proxysql_structs.h"

// Stub for SQLite3_Server_session_handler - required by SQLite3_Server.cpp
// but not used in this test
void SQLite3_Server_session_handler(MySQL_Session* sess, void* _pa, PtrSize_t* pkt) {
	// This test doesn't use SQLite3_Server, so this is just a stub
}


const int MIRROR_HOSTGROUP = 2;
const int FAST_ROUTING_HOSTGROUP = 1;
const int DEFAULT_HOSTGROUP = 0;

// SQLite3 Server port (ProxySQL's built-in SQLite backend)
const int SQLITE3_SERVER_PORT = 6030;

std::vector<std::string> build_cleanup_queries() {
	// Clean up all configuration from any previous test runs
	std::vector<std::string> queries = {
		// Clean up mysql servers and related configurations
		"DELETE FROM mysql_servers",
		"DELETE FROM mysql_servers_ssl_params",
		"DELETE FROM mysql_replication_hostgroups",
		"DELETE FROM mysql_group_replication_hostgroups",
		"DELETE FROM mysql_galera_hostgroups",
		"DELETE FROM mysql_aws_aurora_hostgroups",
		"DELETE FROM mysql_hostgroup_attributes",
		// Clean up query rules
		"DELETE FROM mysql_query_rules",
		"DELETE FROM mysql_query_rules_fast_routing",
		// Clean up users
		"DELETE FROM mysql_users",
		// Clean up firewall rules
		"DELETE FROM mysql_firewall_whitelist_users",
		"DELETE FROM mysql_firewall_whitelist_rules",
		"DELETE FROM mysql_firewall_whitelist_sqli_fingerprints",
		// Load to runtime
		"LOAD MYSQL SERVERS TO RUNTIME",
		"LOAD MYSQL QUERY RULES TO RUNTIME",
		"LOAD MYSQL USERS TO RUNTIME"
	};
	return queries;
}

std::vector<std::string> build_user_queries(const char* username, const char* password) {
	std::vector<std::string> queries = {
		"INSERT INTO mysql_users (username, password, default_hostgroup, default_schema) VALUES ('" +
			std::string(username) + "', '" + std::string(password) + "', " +
			std::to_string(DEFAULT_HOSTGROUP) + ", 'main')",
		"LOAD MYSQL USERS TO RUNTIME"
	};
	return queries;
}

std::vector<std::string> build_setup_queries() {
	std::vector<std::string> queries = {
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '127.0.0.1', " + std::to_string(SQLITE3_SERVER_PORT) + ")",
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (1, '127.0.0.1', " + std::to_string(SQLITE3_SERVER_PORT) + ")",
		"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (2, '127.0.0.1', " + std::to_string(SQLITE3_SERVER_PORT) + ")",
		"LOAD MYSQL SERVERS TO RUNTIME"
	};
	return queries;
}

int run_queries(MYSQL* mysql, std::vector<std::string>& queries) {
	for (const auto& query : queries) {
		diag("Running: %s", query.c_str());
		if (mysql_query(mysql, query.c_str())) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
			return 1;
		}
	}
	return 0;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(3);

	diag("=== Test Configuration ===");
	diag("ProxySQL host: %s, admin port: %d, client port: %d", cl.host, cl.admin_port, cl.port);
	diag("ProxySQL admin user: %s", cl.admin_username);
	diag("ProxySQL client user: %s", cl.username);
	diag("Backend: SQLite3 Server on port %d", SQLITE3_SERVER_PORT);
	diag("Mirror hostgroup: %d", MIRROR_HOSTGROUP);
	diag("Fast routing hostgroup: %d", FAST_ROUTING_HOSTGROUP);
	diag("Default hostgroup: %d", DEFAULT_HOSTGROUP);
	diag("==========================");

	// Initialize admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	diag("Connecting to ProxySQL admin interface at %s:%d...", cl.host, cl.admin_port);
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}
	diag("Successfully connected to ProxySQL admin interface");

	// Clean up any configuration from previous test runs
	diag("=== Cleaning up previous test configuration ===");
	std::vector<std::string> cleanup_queries = build_cleanup_queries();
	if (run_queries(proxysql_admin, cleanup_queries)) {
		return exit_status();
	}
	diag("Cleanup completed");

	// Create test user
	diag("=== Creating test user ===");
	std::vector<std::string> user_queries = build_user_queries(cl.username, cl.password);
	if (run_queries(proxysql_admin, user_queries)) {
		return exit_status();
	}
	diag("Test user '%s' created", cl.username);

	// Setup servers
	diag("=== Setting up test environment ===");
	std::vector<std::string> setup_queries = build_setup_queries();
	if (run_queries(proxysql_admin, setup_queries)) {
		return exit_status();
	}

	// Verify servers are configured
	diag("Verifying mysql_servers configuration:");
	MYSQL_QUERY(proxysql_admin, "SELECT hostgroup_id, hostname, port, status FROM mysql_servers WHERE hostgroup_id IN (0, 1, 2)");
	MYSQL_RES* servers_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW server_row;
	while ((server_row = mysql_fetch_row(servers_res))) {
		diag("  hostgroup=%s, host=%s:%s, status=%s", server_row[0], server_row[1], server_row[2], server_row[3]);
	}
	mysql_free_result(servers_res);

	// Create query rule with mirror_hostgroup=2, apply=0 (no mirror_flagOUT)
	// This rule will mirror the query but not apply, allowing fast routing to be evaluated
	// Note: Using match_pattern instead of match_digest because comments are stripped from digest text
	diag("=== Creating query rules ===");
	std::string mirror_rule = "INSERT INTO mysql_query_rules (rule_id, active, username, match_pattern, mirror_hostgroup, apply) "
		"VALUES (1, 1, '" + std::string(cl.username) + "', 'test_mirror', " +
		std::to_string(MIRROR_HOSTGROUP) + ", 0)";
	diag("Creating mirror query rule: %s", mirror_rule.c_str());
	if (mysql_query(proxysql_admin, mirror_rule.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	// Create fast routing rule with destination_hostgroup=1
	// SQLite3 Server uses 'main' as the default schema
	std::string fast_routing_rule = "INSERT INTO mysql_query_rules_fast_routing "
		"(username, schemaname, flagIN, destination_hostgroup, comment) "
		"VALUES ('" + std::string(cl.username) + "', 'main', 0, " +
		std::to_string(FAST_ROUTING_HOSTGROUP) + ", 'test_fast_routing')";
	diag("Creating fast routing rule: %s", fast_routing_rule.c_str());
	if (mysql_query(proxysql_admin, fast_routing_rule.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	// Load rules to runtime
	diag("Loading query rules to runtime...");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// Verify rules are loaded
	diag("Verifying mysql_query_rules:");
	MYSQL_QUERY(proxysql_admin, "SELECT rule_id, active, username, match_pattern, mirror_hostgroup, apply FROM mysql_query_rules WHERE rule_id=1");
	MYSQL_RES* rules_res = mysql_store_result(proxysql_admin);
	while ((server_row = mysql_fetch_row(rules_res))) {
		diag("  rule_id=%s, active=%s, username=%s, match_pattern=%s, mirror_hostgroup=%s, apply=%s",
			server_row[0], server_row[1], server_row[2], server_row[3], server_row[4], server_row[5]);
	}
	mysql_free_result(rules_res);

	diag("Verifying mysql_query_rules_fast_routing:");
	MYSQL_QUERY(proxysql_admin, "SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM mysql_query_rules_fast_routing");
	MYSQL_RES* fast_rules_res = mysql_store_result(proxysql_admin);
	while ((server_row = mysql_fetch_row(fast_rules_res))) {
		diag("  username=%s, schemaname=%s, flagIN=%s, destination_hostgroup=%s, comment=%s",
			server_row[0], server_row[1], server_row[2], server_row[3], server_row[4]);
	}
	mysql_free_result(fast_rules_res);

	// Initialize client connection
	diag("=== Connecting to ProxySQL client interface ===");
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	diag("Connecting to ProxySQL client interface at %s:%d as user '%s'...", cl.host, cl.port, cl.username);
	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}
	diag("Successfully connected to ProxySQL client interface");

	// Check current schema
	MYSQL_QUERY(proxysql, "SELECT DATABASE()");
	MYSQL_RES* schema_res = mysql_store_result(proxysql);
	server_row = mysql_fetch_row(schema_res);
	diag("Current schema/database: %s", server_row[0] ? server_row[0] : "NULL");
	mysql_free_result(schema_res);

	// Clear stats
	diag("=== Clearing query digest stats ===");
	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(*) FROM stats_mysql_query_digest_reset");
	mysql_free_result(mysql_store_result(proxysql_admin));
	diag("Stats cleared");

	// Execute test query that matches both mirror and fast routing rules
	// The query uses 'test_mirror' in the digest to match the mirror rule
	diag("=== Executing test query ===");
	std::string test_query = "SELECT /* test_mirror */ 1";
	diag("Executing: %s", test_query.c_str());
	MYSQL_QUERY(proxysql, test_query.c_str());
	MYSQL_RES* result = mysql_store_result(proxysql);
	diag("Query executed successfully");
	if (result) {
		server_row = mysql_fetch_row(result);
		diag("Query result: %s", server_row[0] ? server_row[0] : "NULL");
		mysql_free_result(result);
	}

	// Wait a bit for stats to be updated
	diag("Waiting 1 second for stats to be updated...");
	sleep(1);

	// Check stats_mysql_query_digest to verify routing
	diag("=== Checking query routing results ===");
	diag("Expected behavior:");
	diag("  - Original query should go to hostgroup %d (fast routing)", FAST_ROUTING_HOSTGROUP);
	diag("  - Mirror query should go to hostgroup %d (mirror_hostgroup)", MIRROR_HOSTGROUP);

	// Show all digests (the test query is simple: SELECT ?)
	std::string check_all_query = "SELECT hostgroup, schemaname, username, digest_text, count_star "
		"FROM stats_mysql_query_digest";
	diag("Full digest stats: %s", check_all_query.c_str());
	MYSQL_QUERY(proxysql_admin, check_all_query.c_str());
	MYSQL_RES* all_stats_res = mysql_store_result(proxysql_admin);
	diag("Rows returned: %d", (int)mysql_num_rows(all_stats_res));
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(all_stats_res))) {
		diag("  hostgroup=%s, schema=%s, user=%s, digest=%s, count=%s",
			row[0], row[1], row[2], row[3], row[4]);
	}
	mysql_free_result(all_stats_res);

	// Now aggregate by hostgroup for queries from testuser
	std::string check_query = "SELECT hostgroup, SUM(count_star) FROM stats_mysql_query_digest "
		"WHERE username='" + std::string(cl.username) + "' "
		"GROUP BY hostgroup ORDER BY hostgroup";
	diag("Aggregated query: %s", check_query.c_str());
	MYSQL_QUERY(proxysql_admin, check_query.c_str());
	MYSQL_RES* stats_res = mysql_store_result(proxysql_admin);

	int num_rows = mysql_num_rows(stats_res);
	diag("Number of distinct hostgroups used: %d", num_rows);

	// We expect queries in two different hostgroups (1 and 2)
	ok(num_rows == 2, "Queries should be routed to 2 different hostgroups (original + mirror), found: %d", num_rows);

	if (num_rows == 2) {
		int found_hostgroups[2] = {0, 0};
		long found_counts[2] = {0, 0};
		int i = 0;
		while ((row = mysql_fetch_row(stats_res)) && i < 2) {
			int hostgroup = atoi(row[0]);
			long count = atol(row[1]);
			diag("Hostgroup %d: %ld queries (sum of count_star)", hostgroup, count);
			found_hostgroups[i] = hostgroup;
			found_counts[i] = count;
			i++;
		}

		// Verify the hostgroups are correct
		bool has_fast_routing_hg = (found_hostgroups[0] == FAST_ROUTING_HOSTGROUP || found_hostgroups[1] == FAST_ROUTING_HOSTGROUP);
		bool has_mirror_hg = (found_hostgroups[0] == MIRROR_HOSTGROUP || found_hostgroups[1] == MIRROR_HOSTGROUP);

		diag("Verification:");
		diag("  - Has fast routing hostgroup (%d): %s", FAST_ROUTING_HOSTGROUP, has_fast_routing_hg ? "YES" : "NO");
		diag("  - Has mirror hostgroup (%d): %s", MIRROR_HOSTGROUP, has_mirror_hg ? "YES" : "NO");

		ok(has_fast_routing_hg, "Original query should be routed to fast routing hostgroup %d", FAST_ROUTING_HOSTGROUP);
		ok(has_mirror_hg, "Mirror query should be routed to mirror hostgroup %d (NOT overwritten by fast routing)", MIRROR_HOSTGROUP);
	} else {
		// If we didn't get 2 hostgroups, fail the remaining tests
		if (num_rows == 1) {
			row = mysql_fetch_row(stats_res);
			int hostgroup = atoi(row[0]);
			diag("ERROR: All queries went to single hostgroup %d", hostgroup);
			diag("This indicates the bug is present: mirror query's destination_hostgroup was overwritten by fast routing!");
		} else if (num_rows == 0) {
			diag("ERROR: No queries found in stats_mysql_query_digest!");
			diag("This could indicate:");
			diag("  - The query was not executed");
			diag("  - Stats are not being collected");
			diag("  - The query pattern didn't match");
		}
		ok(false, "Original query should be routed to fast routing hostgroup %d", FAST_ROUTING_HOSTGROUP);
		ok(false, "Mirror query should be routed to mirror hostgroup %d", MIRROR_HOSTGROUP);
	}

	mysql_free_result(stats_res);

	// Cleanup
	diag("=== Cleanup ===");
	mysql_close(proxysql);
	diag("Closed client connection");
	mysql_close(proxysql_admin);
	diag("Closed admin connection");
	diag("Test completed");

	return exit_status();
}
