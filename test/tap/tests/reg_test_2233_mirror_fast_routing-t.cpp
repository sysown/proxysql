/**
 * @file reg_test_2233_mirror_fast_routing-t.cpp
 * @brief Regression test for issue #2233: Mirror sessions incorrectly have their
 *        destination_hostgroup overwritten by fast routing rules.
 *
 * This test verifies that:
 * 1. Original queries are routed to the hostgroup specified by fast routing rules
 * 2. Mirror queries are routed to the mirror_hostgroup and NOT overwritten by fast routing
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

std::vector<std::string> setup_queries = {
	"DELETE FROM mysql_servers WHERE hostgroup_id IN (0, 1, 2)",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0, '127.0.0.1', 13306)",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (1, '127.0.0.1', 13306)",
	"INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (2, '127.0.0.1', 13306)",
	"LOAD MYSQL SERVERS TO RUNTIME",
	"DELETE FROM mysql_query_rules",
	"DELETE FROM mysql_query_rules_fast_routing",
	"LOAD MYSQL QUERY RULES TO RUNTIME"
};

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

	// Initialize admin connection
	MYSQL* proxysql_admin = mysql_init(NULL);
	if (!proxysql_admin) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Setup servers and clear rules
	diag("Setting up test environment...");
	if (run_queries(proxysql_admin, setup_queries)) {
		return exit_status();
	}

	// Create query rule with mirror_hostgroup=2, apply=0 (no mirror_flagOUT)
	// This rule will mirror the query but not apply, allowing fast routing to be evaluated
	std::string mirror_rule = "INSERT INTO mysql_query_rules (rule_id, active, username, match_digest, mirror_hostgroup, apply) "
		"VALUES (1, 1, '" + std::string(cl.username) + "', '^SELECT.*test_mirror', " +
		std::to_string(MIRROR_HOSTGROUP) + ", 0)";
	diag("Creating mirror query rule: %s", mirror_rule.c_str());
	if (mysql_query(proxysql_admin, mirror_rule.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	// Create fast routing rule with destination_hostgroup=1
	std::string fast_routing_rule = "INSERT INTO mysql_query_rules_fast_routing "
		"(username, schemaname, flagIN, destination_hostgroup, comment) "
		"VALUES ('" + std::string(cl.username) + "', 'information_schema', 0, " +
		std::to_string(FAST_ROUTING_HOSTGROUP) + ", 'test_fast_routing')";
	diag("Creating fast routing rule: %s", fast_routing_rule.c_str());
	if (mysql_query(proxysql_admin, fast_routing_rule.c_str())) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return exit_status();
	}

	// Load rules to runtime
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// Initialize client connection
	MYSQL* proxysql = mysql_init(NULL);
	if (!proxysql) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return -1;
	}

	if (!mysql_real_connect(proxysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql));
		return exit_status();
	}

	// Clear stats
	MYSQL_QUERY(proxysql_admin, "SELECT COUNT(*) FROM stats_mysql_query_digest_reset");
	mysql_free_result(mysql_store_result(proxysql_admin));

	// Execute test query that matches both mirror and fast routing rules
	// The query uses 'test_mirror' in the digest to match the mirror rule
	diag("Executing test query that matches both mirror and fast routing rules...");
	std::string test_query = "SELECT /* test_mirror */ 1";
	MYSQL_QUERY(proxysql, test_query.c_str());
	MYSQL_RES* result = mysql_store_result(proxysql);
	mysql_free_result(result);

	// Wait a bit for stats to be updated
	sleep(1);

	// Check stats_mysql_query_digest to verify routing
	// We expect:
	// - Original query routed to FAST_ROUTING_HOSTGROUP (1)
	// - Mirror query routed to MIRROR_HOSTGROUP (2)
	std::string check_query = "SELECT hostgroup, COUNT(*) FROM stats_mysql_query_digest "
		"WHERE digest_text LIKE '%test_mirror%' "
		"GROUP BY hostgroup ORDER BY hostgroup";
	diag("Checking query routing: %s", check_query.c_str());
	MYSQL_QUERY(proxysql_admin, check_query.c_str());
	MYSQL_RES* stats_res = mysql_store_result(proxysql_admin);

	int num_rows = mysql_num_rows(stats_res);
	diag("Number of distinct hostgroups used: %d", num_rows);

	// We expect queries in two different hostgroups (1 and 2)
	ok(num_rows == 2, "Queries should be routed to 2 different hostgroups (original + mirror), found: %d", num_rows);

	if (num_rows == 2) {
		MYSQL_ROW row;
		int found_hostgroups[2] = {0, 0};
		int i = 0;
		while ((row = mysql_fetch_row(stats_res)) && i < 2) {
			int hostgroup = atoi(row[0]);
			long count = atol(row[1]);
			diag("Hostgroup %d: %ld queries", hostgroup, count);
			found_hostgroups[i++] = hostgroup;
		}

		// Verify the hostgroups are correct
		bool has_fast_routing_hg = (found_hostgroups[0] == FAST_ROUTING_HOSTGROUP || found_hostgroups[1] == FAST_ROUTING_HOSTGROUP);
		bool has_mirror_hg = (found_hostgroups[0] == MIRROR_HOSTGROUP || found_hostgroups[1] == MIRROR_HOSTGROUP);

		ok(has_fast_routing_hg, "Original query should be routed to fast routing hostgroup %d", FAST_ROUTING_HOSTGROUP);
		ok(has_mirror_hg, "Mirror query should be routed to mirror hostgroup %d (NOT overwritten by fast routing)", MIRROR_HOSTGROUP);
	} else {
		// If we didn't get 2 hostgroups, fail the remaining tests
		if (num_rows == 1) {
			MYSQL_ROW row = mysql_fetch_row(stats_res);
			int hostgroup = atoi(row[0]);
			diag("ERROR: All queries went to single hostgroup %d", hostgroup);
			diag("This indicates the bug is present: mirror query's destination_hostgroup was overwritten by fast routing!");
		}
		ok(false, "Original query should be routed to fast routing hostgroup %d", FAST_ROUTING_HOSTGROUP);
		ok(false, "Mirror query should be routed to mirror hostgroup %d", MIRROR_HOSTGROUP);
	}

	mysql_free_result(stats_res);

	// Cleanup
	mysql_close(proxysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
