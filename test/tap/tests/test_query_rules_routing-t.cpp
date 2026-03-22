/**
 * @file test_query_rules_routing-t.cpp
 * @brief This test is an initial version for testing query routing to
 *  different hostgroups through 'query rules'. It aims to check that
 *  arbitrary query rules are properly matched and queries are executed in
 *  the target hostgroups for both 'text protocol' and 'prepared statements'.
 */

#include <algorithm>
#include <cstring>
#include <cmath>
#include <chrono>
#include <climits>
#include <numeric>
#include <memory>
#include <string>
#include <stdio.h>
#include <vector>
#include <tuple>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "command_line.h"
#include "proxysql_utils.h"
#include "tap.h"
#include "utils.h"

int g_seed = 0;

inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}

void gen_random_str(char *s, const int len) {
	g_seed = monotonic_time() ^ getpid() ^ pthread_self();
	static const char alphanum[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

/**
 * @brief For now a query rules test for destination hostgroup is going
 *   to consist into:
 *
 *   - A set of rules to apply.
 *   - A set of queries to exercise those rules.
 *   - The destination hostgroup in which the queries are supposed to end.
 */
using dst_hostgroup_test =
	std::pair<std::vector<std::string>, std::vector<std::pair<std::string, int>>>;


/**
 * @brief All supplied queries should be unique, to know that two queries
 *   are going to be executed in the backend when a prepared statement
 *   is executed: <PREPARE + EXECUTE>
 */
std::vector<dst_hostgroup_test> dst_hostgroup_tests {
	{
		{
			"INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
			" VALUES (1,1,'^SELECT.*FOR UPDATE',0,1)",
			"INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
			" VALUES (2,1,'^SELECT',1,1)"
		},
		{
			{
				"SELECT /* ;%s */ 1",
				1
			},
			{
				"SELECT /* ;%s */ c FROM test.reg_test_3427_0 WHERE id=1",
				1
			},
			{
				"SELECT /* ;%s */ c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 20",
				1
			},
			{
				"SELECT /* ;%s */ SUM(k) c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 10",
				1
			},
			{
				"INSERT /* ;%s */ INTO test.reg_test_3427_0 (k) VALUES (2)",
				0
			},
			{
				"UPDATE /* ;%s */ test.reg_test_3427_0 SET pad=\"random\" WHERE id=2",
				0
			},
			{
				"SELECT DISTINCT /* ;%s */ c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 10 ORDER BY c",
				1
			}
		}
	},
	{
		{
			"INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
			" VALUES (1,1,'^SELECT.*FROM test.reg_test_3427_0 .*',1,1)",
			"INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
			" VALUES (2,1,'^SELECT.*FROM test.reg_test_3427_1 .*',0,1)",
		},
		{
			{
				"UPDATE /* ;%s */ test.reg_test_3427_0 SET pad=\"random\" WHERE id=2",
				0
			},
			{
				"SELECT DISTINCT /* ;%s */ c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 10 ORDER BY c",
				1
			},
			{
				"SELECT /* ;%s */ c FROM test.reg_test_3427_1 WHERE id BETWEEN 1 AND 10 ORDER BY c",
				0
			},
			{
				"INSERT /* ;%s */ INTO test.reg_test_3427_0 (k) VALUES (2)",
				0
			},
			{
				"SELECT DISTINCT /* ;hostgroup=0;%s */ c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 10 ORDER BY c",
				0
			},
		}
	},
	{
		{
			"INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
			" VALUES (1,1,'^SELECT.*FOR UPDATE',0,1)",
			"INSERT INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
			" VALUES (2,1,'^SELECT',1,1)"
		},
		{
			{
				"UPDATE /* ;%s */ test.reg_test_3427_0 SET pad=\"random\" WHERE id=2",
				0
			},
			{
				"SELECT /* ;hostgroup=0;%s */ c FROM test.reg_test_3427_0 WHERE id=1",
				0
			},
			{
				"SELECT /* ;hostgroup=0;%s */ c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 20",
				0
			},
			{
				"SELECT /* ;hostgroup=0;%s */ SUM(k) c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 10",
				0
			},
			{
				"SELECT /* ;%s */ c FROM test.reg_test_3427_0 WHERE id=1",
				1
			},
			{
				"SELECT /* ;%s */ c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 20",
				1
			},
			{
				"SELECT /* ;%s */ SUM(k) c FROM test.reg_test_3427_0 WHERE id BETWEEN 1 AND 10",
				1
			}
		}
	}
};

/**
 * @brief Get the current query count for a specific hostgroup.
 *
 * @param proxysql_admin A already opened MYSQL connection to ProxySQL admin
 *   interface.
 * @param hostgroup_id The 'hostgroup_id' from which get the query count.
 *
 * @return The number of queries that have been executed in that hostgroup id.
 */
int get_hostgroup_query_count(MYSQL* proxysql_admin, const int hostgroup_id) {
	if (proxysql_admin == NULL) {
		return EXIT_FAILURE;
	}

	int query_count = -1;

	std::string t_query {
		"SELECT SUM(Queries) FROM stats.stats_mysql_connection_pool WHERE hostgroup=%d"
	};
	std::string query {};
	string_format(t_query, query, hostgroup_id);

	MYSQL_QUERY(proxysql_admin, query.c_str());
	MYSQL_RES* sum_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW row = mysql_fetch_row(sum_res);

	if (row[0]) {
		query_count = atoi(row[0]);
	}

	mysql_free_result(sum_res);

	return query_count;
}

/**
 * @brief Simple function that performs a text protocol query and discards the result.
 *
 * @param proxysql A already opened MYSQL connection to ProxySQL.
 * @param query The query to be executed.
 *
 * @return The error code of executing the query.
 */
int perform_text_procotol_query(MYSQL* proxysql, const std::string& query) {
	int rc = mysql_query(proxysql, query.c_str());

	if (rc == 0) {
		MYSQL_RES* query_res = mysql_store_result(proxysql);

		if (query_res) {
			mysql_free_result(query_res);
		}
	}

	return rc;
}

/**
 * @brief Simple function that performs a stmt query and discards the result.
 *
 * @param proxysql A already opened MYSQL connection to ProxySQL.
 * @param query The query to be executed.
 *
 * @return The error code of executing the query.
 */
int perform_stmt_query(MYSQL* proxysql, const std::string& query) {
	int rc = EXIT_FAILURE;

	MYSQL_STMT* stmt = mysql_stmt_init(proxysql);
	if (stmt == NULL) { return EXIT_FAILURE; }

	rc = mysql_stmt_prepare(stmt, query.c_str(), strlen(query.c_str()));
	if (rc) { return EXIT_FAILURE; }

	rc = mysql_stmt_execute(stmt);
	if (rc) { return EXIT_FAILURE; }

	rc = mysql_stmt_close(stmt);
	if (rc) { return EXIT_FAILURE; }

	return rc;
}

/**
 * @brief Simple helper function for creating a 'sysbench'
 *   alike testing table.
 *
 * @param proxysql A already opened MYSQL connection to ProxySQL.
 *
 * @return EXIT_FAILURE in case of failure or EXIT_SUCCESS otherwise.
 */
int create_testing_tables(MYSQL* proxysql, uint32_t num_tables) {
	if (proxysql == NULL) { return EXIT_FAILURE; }

	MYSQL_QUERY(proxysql, "CREATE DATABASE IF NOT EXISTS test");

	for (uint32_t i = 0; i < num_tables; i++) {
		std::string t_drop_table_query {
			"DROP TABLE IF EXISTS test.reg_test_3427_%d"
		};
		std::string t_create_table_query {
			"CREATE TABLE IF NOT EXISTS test.reg_test_3427_%d ("
			"    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,"
			"    `k` int(11) NOT NULL DEFAULT '0',"
			"    `c` char(120) NOT NULL DEFAULT '',"
			"    `pad` char(60) NOT NULL DEFAULT '',"
			"    KEY `k_1` (`k`)"
			")"
		};
		std::string t_insert_trivial_val {
			"INSERT INTO test.reg_test_3427_%d (k, c, pad) VALUES (3427, 'foo', 'bar')"
		};

		// Format the queries
		std::string drop_table_query {};
		string_format(t_drop_table_query, drop_table_query, i);

		std::string create_table_query {};
		string_format(t_create_table_query, create_table_query, i);

		std::string insert_trivial_val {};
		string_format(t_insert_trivial_val, insert_trivial_val, i);

		// Perform the queries
		MYSQL_QUERY(proxysql, drop_table_query.c_str());
		MYSQL_QUERY(proxysql, create_table_query.c_str());
		// Insert trivial value, we are only interesting in routing
		MYSQL_QUERY(proxysql, insert_trivial_val.c_str());
	}

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	diag("Test query rules routing functionality");
	diag("This test validates that queries are routed to correct hostgroups based on query rules");

	plan(dst_hostgroup_tests.size());

	MYSQL* proxysql_admin = mysql_init(NULL);
	MYSQL* proxysql_text = mysql_init(NULL);
	MYSQL* proxysql_stmt = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_text, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_text));
		return -1;
	}
	if (!mysql_real_connect(proxysql_stmt, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_stmt));
		return -1;
	}
	if (!mysql_real_connect(proxysql_admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return -1;
	}

	// Disable 'auto_increment_delay_multiplex' for avoiding unintentionally
	// disabling multiplexing due to inserts.
	MYSQL_QUERY(proxysql_admin, "SET mysql-auto_increment_delay_multiplex=0");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Debug: Show current server configuration
	diag("=== Current mysql_servers configuration ===");
	MYSQL_QUERY(proxysql_admin, "SELECT hostgroup_id, hostname, port, status FROM mysql_servers ORDER BY hostgroup_id");
	MYSQL_RES* servers_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW server_row;
	while ((server_row = mysql_fetch_row(servers_res))) {
		diag("  hostgroup=%s, hostname=%s, port=%s, status=%s",
			server_row[0], server_row[1], server_row[2], server_row[3]);
	}
	mysql_free_result(servers_res);

	// Debug: Show user's default hostgroup
	diag("=== Current mysql_users configuration ===");
	MYSQL_QUERY(proxysql_admin, "SELECT username, default_hostgroup FROM mysql_users WHERE username='root' OR username='sbtest1' LIMIT 5");
	MYSQL_RES* users_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW user_row;
	while ((user_row = mysql_fetch_row(users_res))) {
		diag("  username=%s, default_hostgroup=%s", user_row[0], user_row[1]);
	}
	mysql_free_result(users_res);

	// Discover the actual writer and reader hostgroups from the infrastructure
	// The test uses hostgroups 0 and 1, but the infrastructure may use different ones (e.g., 1300, 1301)
	int writer_hg = 0;
	int reader_hg = 1;

	// Try to discover writer hostgroup from user's default_hostgroup
	// Use runtime_mysql_users since mysql_users may be empty in some configurations
	MYSQL_QUERY(proxysql_admin, "SELECT default_hostgroup FROM runtime_mysql_users WHERE username='root' LIMIT 1");
	MYSQL_RES* hg_res = mysql_store_result(proxysql_admin);
	MYSQL_ROW hg_row = mysql_fetch_row(hg_res);
	if (hg_row && hg_row[0]) {
		writer_hg = atoi(hg_row[0]);
		diag("Discovered writer hostgroup from runtime_mysql_users 'root': %d", writer_hg);
	}
	mysql_free_result(hg_res);

	// Try to discover reader hostgroup from mysql_replication_hostgroups
	// First, check if there's a replication hostgroup entry for the writer hostgroup
	char rep_hg_query[256];
	snprintf(rep_hg_query, sizeof(rep_hg_query),
		"SELECT writer_hostgroup, reader_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=%d LIMIT 1",
		writer_hg);
	MYSQL_QUERY(proxysql_admin, rep_hg_query);
	hg_res = mysql_store_result(proxysql_admin);
	hg_row = mysql_fetch_row(hg_res);
	if (hg_row && hg_row[0] && hg_row[1]) {
		writer_hg = atoi(hg_row[0]);
		reader_hg = atoi(hg_row[1]);
		diag("Discovered hostgroups from mysql_replication_hostgroups: writer=%d, reader=%d", writer_hg, reader_hg);
		mysql_free_result(hg_res);
	} else {
		mysql_free_result(hg_res);
		// Fallback: query runtime_mysql_servers to find hostgroups with servers in ONLINE status
		MYSQL_QUERY(proxysql_admin, "SELECT DISTINCT hostgroup_id FROM runtime_mysql_servers WHERE status='ONLINE' ORDER BY hostgroup_id LIMIT 2");
		hg_res = mysql_store_result(proxysql_admin);
		std::vector<int> online_hostgroups;
		while ((hg_row = mysql_fetch_row(hg_res))) {
			online_hostgroups.push_back(atoi(hg_row[0]));
		}
		mysql_free_result(hg_res);

		if (online_hostgroups.size() >= 2) {
			// We have at least 2 hostgroups - use the first two for writer and reader
			writer_hg = online_hostgroups[0];
			reader_hg = online_hostgroups[1];
			diag("Discovered hostgroups from runtime_mysql_servers: writer=%d, reader=%d", writer_hg, reader_hg);
		} else if (online_hostgroups.size() == 1) {
			writer_hg = online_hostgroups[0];
			reader_hg = writer_hg;  // Use same hostgroup if only one exists
			diag("Only one hostgroup found: writer=%d, reader=%d (same)", writer_hg, reader_hg);
		}
	}

	// Now update the test data with the discovered hostgroups
	diag("Updating test query rules to use discovered hostgroups: writer=%d, reader=%d", writer_hg, reader_hg);

	// Update dst_hostgroup_tests with dynamic hostgroups
	for (auto& test : dst_hostgroup_tests) {
		for (auto& rule : test.first) {
			// Replace hardcoded hostgroups with discovered ones
			// Pattern: destination_hostgroup,0 -> destination_hostgroup,WRITER_HG
			// Pattern: destination_hostgroup,1 -> destination_hostgroup,READER_HG
			size_t pos;
			pos = rule.find(",0,1)");
			if (pos != std::string::npos) {
				rule.replace(pos, 5, "," + std::to_string(writer_hg) + ",1)");
			}
			pos = rule.find(",1,1)");
			if (pos != std::string::npos) {
				rule.replace(pos, 5, "," + std::to_string(reader_hg) + ",1)");
			}
			pos = rule.find(",0,1)");  // Check again for any remaining
			if (pos != std::string::npos) {
				rule.replace(pos, 5, "," + std::to_string(writer_hg) + ",1)");
			}
		}
		for (auto& query_hid : test.second) {
			// Update expected hostgroups in queries
			if (query_hid.second == 0) {
				query_hid.second = writer_hg;
			} else if (query_hid.second == 1) {
				query_hid.second = reader_hg;
			}

			// Also update query hints that specify hostgroup=0 to use the actual writer hostgroup
			// ProxySQL query hints like /* ;hostgroup=0;... */ need to be updated
			size_t hint_pos = query_hid.first.find("hostgroup=0");
			if (hint_pos != std::string::npos) {
				query_hid.first.replace(hint_pos, 11, "hostgroup=" + std::to_string(writer_hg));
				diag("Updated query hint from hostgroup=0 to hostgroup=%d", writer_hg);
			}
		}
	}

	diag("Updated test configuration with dynamic hostgroups");

	// Create the testing table
	int c_table_res = create_testing_tables(proxysql_text, 2);
	if (c_table_res) { return EXIT_FAILURE; }

	const std::string rep_check_query {
		"SELECT CASE WHEN (SELECT COUNT(*) FROM test.reg_test_3427_0 WHERE id=1) = 1 THEN 'TRUE' ELSE 'FALSE' END"
	};
	int rep_err = wait_for_replication(proxysql_text, proxysql_admin, rep_check_query, 10, 1);
	if (rep_err) {
		fprintf(stderr,
			"File %s, line %d, Error: %s\n",
			__FILE__, __LINE__, "Waiting for replication failed."
		);
		return EXIT_FAILURE;
	}

	for (const auto& dst_hostgroup_test : dst_hostgroup_tests) {
		const auto& query_rules = dst_hostgroup_test.first;
		const auto& queries_hids = dst_hostgroup_test.second;

		// First prepare the query rules
		// ********************************************************************
		MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules");

		for (const auto& query_rule : query_rules) {
			MYSQL_QUERY(proxysql_admin, query_rule.c_str());
		}

		MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

		// ********************************************************************

		// Secondly execute the queries and check the hostgroup
		// ********************************************************************

		bool queries_properly_routed = true;
		std::vector<std::string> text_queries_failed_to_route {};
		std::vector<std::string> stmt_queries_failed_to_route {};

		for (const auto& query_hid : queries_hids) {
			// Create an unique query
			std::string query {};
			std::string rnd_str(static_cast<std::size_t>(20), '\0');
			gen_random_str(&rnd_str[0], 20);
			string_format(query_hid.first, query, rnd_str.c_str());

			diag("Testing query: '%s' (expected hostgroup: %d)", query.c_str(), query_hid.second);

			// First execute the query for text protocol
			// ********************************************************************

			// Get the current hosgtroup queries
			int cur_hid_queries = get_hostgroup_query_count(proxysql_admin, query_hid.second);
			diag("  Text protocol: current query count for HG %d = %d", query_hid.second, cur_hid_queries);

			// Perform the query in a text protocol connection
			int text_prot_res = perform_text_procotol_query(proxysql_text, query);
			if (text_prot_res) {
				diag(
					"Executing 'text_protocol' query: '%s' failed with err code: '%d'",
					query.c_str(),
					text_prot_res
				);
				return EXIT_FAILURE;
			}

			// Get the new hosgtroup queries
			int new_hid_queries = get_hostgroup_query_count(proxysql_admin, query_hid.second);
			diag("  Text protocol: new query count for HG %d = %d (diff=%d, expected=1)",
				query_hid.second, new_hid_queries, new_hid_queries - cur_hid_queries);

			if (new_hid_queries - cur_hid_queries != 1) {
				queries_properly_routed = false;
				text_queries_failed_to_route.push_back(query);
				diag("  Text protocol: QUERY FAILED TO ROUTE to expected hostgroup %d", query_hid.second);
			}

			// Secondly execute the query for binary protocol
			// ********************************************************************

			// Get the current hosgtroup queries
			cur_hid_queries = get_hostgroup_query_count(proxysql_admin, query_hid.second);
			diag("  Binary protocol: current query count for HG %d = %d", query_hid.second, cur_hid_queries);

			// Perform the query in a stmt protocol connection
			int stmt_res = perform_stmt_query(proxysql_stmt, query);
			if (stmt_res) {
				diag(
					"Executing 'stmt' query: '%s' failed with err code: '%d', err: '%s'",
					query.c_str(),
					stmt_res,
					mysql_error(proxysql_stmt)
				);
				return EXIT_FAILURE;
			}

			// Get the new hosgtroup queries
			new_hid_queries = get_hostgroup_query_count(proxysql_admin, query_hid.second);
			diag("  Binary protocol: new query count for HG %d = %d (diff=%d, expected=2)",
				query_hid.second, new_hid_queries, new_hid_queries - cur_hid_queries);

			if (new_hid_queries - cur_hid_queries != 2) {
				queries_properly_routed = false;
				stmt_queries_failed_to_route.push_back(query);
				diag("  Binary protocol: QUERY FAILED TO ROUTE to expected hostgroup %d", query_hid.second);
			}
		}

		if (queries_properly_routed == false) {
			std::string str_query_rules =
				std::accumulate(
					query_rules.begin(),
					query_rules.end(),
					std::string {},
					[](const std::string& a, const std::string& b) -> std::string {
						return a + (a.length() > 0 ? "\n" : "") + b;
					}
				);

			std::string str_text_queries =
				std::accumulate(
					text_queries_failed_to_route.begin(),
					text_queries_failed_to_route.end(),
					std::string {},
					[](const std::string& a, const std::string& b) -> std::string {
						return a + (a.length() > 0 ? "\n" : "") + b;
					}
				);

			std::string str_stmt_queries =
				std::accumulate(
					stmt_queries_failed_to_route.begin(),
					stmt_queries_failed_to_route.end(),
					std::string {},
					[](const std::string& a, const std::string& b) -> std::string {
						return a + (a.length() > 0 ? "\n" : "") + b;
					}
				);

			diag(
				"Test with rules:\n\n%s\n\nFailed to route the following text queries:\n\n%s\n",
				str_query_rules.c_str(),
				str_text_queries.c_str()
			);

			diag(
				"Test with rules:\n\n%s\n\nFailed to route the following stmt queries:\n\n%s\n",
				str_query_rules.c_str(),
				str_stmt_queries.c_str()
			);
		}

		ok(queries_properly_routed, "Queries for test were properly routed to the target hostgroups");
	}

	mysql_close(proxysql_admin);
	mysql_close(proxysql_stmt);
	mysql_close(proxysql_text);

	return exit_status();
}
