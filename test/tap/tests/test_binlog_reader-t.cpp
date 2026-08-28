/**
 * @file binlog_reader_test-t.cpp
 * @brief This tests verifies ProxySQL integration with proxysql_mysqlbinlog utility for achieving GTID
 *  consistency.
 * @details The test performs two different type of checks:
 *   * Hostgroup and Queries_GTID_sync tracking:
 *
 *     Test performs a number of UPDATE and SELECTS, and later checks that 'Queries_GTID_sync' from
 *     'stats_mysql_connection_pool' matches the expected values:
 *
 *     1. It checks that sessions in which DML have been issued are GTID tracked.
 *     2. Checks that sessions in which DML have NOT been issued are NOT GITD tracked.
 *
 *   * Dirty reads check:
 *
 *     Test perform UPDATE and SELECT operations, checking that the received value matches the expected one.
 *     If not, replication hasn't properly catchup and a dirty read has been received.
 *
 *     NOTE: At this moment the test dirty read max failure rate is set at '5%'.
 */

#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <string>
#include <stdio.h>
#include <utility>
#include <vector>

#include "mysql.h"
#include "mysqld_error.h"
#include "json.hpp"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"

using std::pair;
using std::string;
using std::vector;
using std::map;

using nlohmann::json;

int create_testing_tables(MYSQL* mysql_server) {
	// Create the testing database
	fprintf(stderr, "--- create_testing_tables() called ---\n");
	fprintf(stderr, "Creating test database...\n");
	MYSQL_QUERY(mysql_server, "CREATE DATABASE IF NOT EXISTS test");
	fprintf(stderr, "Dropping existing test.gtid_test table if present...\n");
	MYSQL_QUERY(mysql_server, "DROP TABLE IF EXISTS test.gtid_test");

	MYSQL_QUERY(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS test.gtid_test ("
		"  id INTEGER NOT NULL AUTO_INCREMENT,"
		"  a INT NOT NULL,"
		"  c varchar(255),"
		"  pad CHAR(60),"
		"  PRIMARY KEY (id)"
		")"
	);

	return EXIT_SUCCESS;
}

int insert_random_data(MYSQL* proxysql_mysql, uint32_t rows) {
	[[maybe_unused]] int rnd_a = rand() % 1000;
	string rnd_c = random_string(rand() % 100 + 5);
	string rnd_pad = random_string(rand() % 50 + 5);

	for (uint32_t i = 0; i < rows; i++) {
		string update_query {};
		string_format(
			"INSERT INTO test.gtid_test (a, c, pad) VALUES ('%d', '%s', '%s')", update_query,
			i, rnd_c.c_str(), rnd_pad.c_str()
		);
		MYSQL_QUERY(proxysql_mysql, update_query.c_str());
	}

	return EXIT_SUCCESS;
}

int perform_update(MYSQL* proxysql_mysql, uint32_t rows) {
	[[maybe_unused]] int rnd_a = rand() % 1000;

	string query { "UPDATE test.gtid_test SET a=a+1, c=REVERSE(c)" };
	MYSQL_QUERY(proxysql_mysql, query.c_str());

	return EXIT_SUCCESS;
}

const double MAX_FAILURE_PCT = 15.0;
const uint32_t NUM_ROWS = 3000;
const uint32_t NUM_CHECKS = 500;

// Writer and reader hostgroups - configurable via environment variables WHG/RHG
// Defaults to 1200/1201 for backward compatibility with legacy-binlog (PREFIX=12)
static uint32_t WHG = 1200;
static uint32_t RHG = 1201;

map<uint32_t, pair<uint32_t,uint32_t>> extract_hosgtroups_stats(const vector<mysql_res_row>& conn_pool_stats) {
	uint32_t hg_whg_queries = 0;
	uint32_t hg_whg_sync_queries = 0;
	uint32_t hg_rhg_queries = 0;
	uint32_t hg_rhg_sync_queries = 0;

	for (const auto& conn_pool_stats_row : conn_pool_stats) {
		if (conn_pool_stats_row.size() < 3) {
			const char* msg = "Invalid result received from 'stats.stats_mysql_connection_pool'";
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, msg);
			return {};
		}

		const uint32_t hg = std::stol(conn_pool_stats_row[0]);
		const uint32_t queries = std::stol(conn_pool_stats_row[1]);
		const uint32_t queries_gtid_sync = std::stol(conn_pool_stats_row[2]);

		if (hg == WHG) {
			hg_whg_queries += queries;
			hg_whg_sync_queries += queries_gtid_sync;
		} else if (hg == RHG) {
			hg_rhg_queries += queries;
			hg_rhg_sync_queries += queries_gtid_sync;
		}
	}

	return { { WHG, { hg_whg_queries, hg_whg_sync_queries } }, { RHG, { hg_rhg_queries, hg_rhg_sync_queries } } };
}

int perform_rnd_selects(const CommandLine& cl, uint32_t NUM) {
	// Check connections only performing select doesn't contribute to GITD count
	fprintf(stderr, "\n");
	fprintf(stderr, "--- perform_rnd_selects() called ---\n");
	fprintf(stderr, "  Parameters:\n");
	fprintf(stderr, "    Host: %s\n", cl.host ? cl.host : "(null)");
	fprintf(stderr, "    Port: %d\n", cl.port);
	fprintf(stderr, "    User: sbtest8 / sbtest8 (hardcoded)\n");
	fprintf(stderr, "    Number of SELECTs to perform: %d\n", NUM);
	fprintf(stderr, "\n");

	MYSQL* select_conn = mysql_init(NULL);

	if (select_conn == NULL) {
		fprintf(stderr, "FATAL: mysql_init() failed in perform_rnd_selects\n");
		return EXIT_FAILURE;
	}

	fprintf(stderr, "Connecting as sbtest8 for SELECT-only operations...\n");
	if (!mysql_real_connect(select_conn, cl.host, "sbtest8", "sbtest8", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(select_conn));
		fprintf(stderr, "\n");
		fprintf(stderr, "DIAGNOSTIC: Failed to connect as sbtest8 in perform_rnd_selects\n");
		fprintf(stderr, "  This connection uses hardcoded credentials: sbtest8 / sbtest8\n");
		fprintf(stderr, "  Ensure 'sbtest8' user is configured in ProxySQL mysql_users table\n");
		fprintf(stderr, "\n");
		mysql_close(select_conn);
		return EXIT_FAILURE;
	}
	fprintf(stderr, "Connected successfully as sbtest8 for SELECT operations\n");

	for (uint32_t i = 0; i < NUM; i++) {
		int r_row = rand() % static_cast<int>(NUM_ROWS);
		if (r_row == 0) { r_row = 1; }

		string s_query {};
		string_format("SELECT * FROM test.gtid_test WHERE id=%d", s_query, r_row);

		int rc = mysql_query(select_conn, s_query.c_str());
		if (rc != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(select_conn));
			mysql_close(select_conn);
			return EXIT_FAILURE;
		}
		mysql_free_result(mysql_store_result(select_conn));
	}

	mysql_close(select_conn);

	return EXIT_SUCCESS;
}

int check_gitd_tracking(const CommandLine& cl, MYSQL* proxysql_mysql, MYSQL* proxysql_admin) {
	// Check that all queries were routed to the correct hostgroup
	MYSQL_QUERY(proxysql_admin, "SELECT hostgroup, queries, Queries_GTID_sync FROM stats.stats_mysql_connection_pool");
	MYSQL_RES* conn_pool_stats_myres = mysql_store_result(proxysql_admin);
	vector<mysql_res_row> conn_pool_stats { extract_mysql_rows(conn_pool_stats_myres) };
	mysql_free_result(conn_pool_stats_myres);

	if (conn_pool_stats.size() == 0) {
		const char* msg = "Invalid result received from 'stats.stats_mysql_connection_pool'";
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, msg);
		return EXIT_FAILURE;
	}

	auto hg_stats { extract_hosgtroups_stats(conn_pool_stats) };
	uint32_t hg_whg_queries = hg_stats.at(WHG).first;
	uint32_t hg_whg_sync_queries = hg_stats.at(WHG).second;;
	uint32_t hg_rhg_queries = hg_stats.at(RHG).first;
	uint32_t hg_rhg_sync_queries = hg_stats.at(RHG).second;;

	uint32_t hg_whg_exp_queries =
		3 +            // Database creation + Table DROP + Table creation
		NUM_ROWS +     // Initial data load
		NUM_CHECKS;    // Updates (matching number of checks)
	uint32_t hg_whg_exp_sync_queries = NUM_CHECKS - 1;

	bool hg_whg_checks = hg_whg_exp_queries == hg_whg_queries && hg_whg_sync_queries == hg_whg_exp_sync_queries;
	bool hg_rhg_checks = hg_rhg_queries == NUM_CHECKS && hg_rhg_sync_queries == NUM_CHECKS;

	ok(
		hg_whg_checks && hg_rhg_checks,
		"GTID based query routing: {"
			" hg_%d: { exp_queries: %d, act_queries: %d, exp_sync_queries: %d, act_sync_queries: %d },"
			" hg_%d: { exp_queries: %d, act_queries: %d, exp_sync_queries: %d, act_sync_queries: %d }"
		" }",
		WHG, hg_whg_exp_queries, hg_whg_queries, hg_whg_exp_sync_queries, hg_whg_sync_queries,
		RHG, NUM_CHECKS, hg_rhg_queries, NUM_CHECKS, hg_rhg_queries
	);

	// Reset connection pool stats
	int rc = mysql_query(proxysql_admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset");
	if (rc != EXIT_SUCCESS) { return EXIT_FAILURE; }
	mysql_free_result(mysql_store_result(proxysql_admin));

	// Perform random selects, no prior updates in the connection, no GTID tracking should take place
	rc = perform_rnd_selects(cl, NUM_CHECKS / 5);
	if (rc != EXIT_SUCCESS) { return EXIT_FAILURE; }

	// Update stats
	MYSQL_QUERY(proxysql_admin, "SELECT hostgroup, queries, Queries_GTID_sync FROM stats.stats_mysql_connection_pool");
	conn_pool_stats_myres = mysql_store_result(proxysql_admin);
	conn_pool_stats = extract_mysql_rows(conn_pool_stats_myres);
	mysql_free_result(conn_pool_stats_myres);

	// Extract stats
	hg_stats = extract_hosgtroups_stats(conn_pool_stats);
	hg_whg_queries = hg_stats.at(WHG).first;
	hg_whg_sync_queries = hg_stats.at(WHG).second;;
	hg_rhg_queries = hg_stats.at(RHG).first;
	hg_rhg_sync_queries = hg_stats.at(RHG).second;;

	uint32_t hg_rhg_exp_queries = NUM_CHECKS / 5;
	ok(
		hg_whg_queries == 0 && hg_whg_sync_queries == 0 && hg_rhg_queries == hg_rhg_exp_queries && hg_rhg_sync_queries == 0,
		"Queries should only be executed in 'HG %d' and no GTID sync should take place: {"
		" hg_%d: { exp_queries: 0, act_queries: %d, exp_sync_queries: 0, act_sync_queries: %d },"
		" hg_%d: { exp_queries: %d, act_queries: %d, exp_sync_queries: 0, act_sync_queries: %d },"
		" }",
		RHG,
		WHG, hg_whg_queries, hg_whg_sync_queries, RHG, hg_rhg_exp_queries, hg_rhg_queries, hg_rhg_sync_queries
	);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	// ================================================================================
	// TEST: test_binlog_reader-t
	// PURPOSE: Verifies ProxySQL integration with proxysql_mysqlbinlog utility for
	//          achieving GTID consistency.
	//
	// DESCRIPTION:
	//   This test performs two types of checks:
	//   1. Hostgroup and Queries_GTID_sync tracking:
	//      - Sessions with DML are GTID tracked
	//      - Sessions without DML are NOT GTID tracked
	//   2. Dirty reads check:
	//      - UPDATE and SELECT operations verify expected values
	//      - Detects if replication hasn't caught up (dirty reads)
	//
	// CONNECTION SETTINGS:
	//   - ProxySQL MySQL Interface: host=%s, port=%d
	//   - ProxySQL Admin Interface: host=%s, port=%d
	//   - MySQL User: sbtest8 / sbtest8 (hardcoded test credentials)
	//   - Admin User: %s / %s (from environment)
	//
	// CONSTANTS:
	//   - MAX_FAILURE_PCT: %.1f%%
	//   - NUM_ROWS: %d
	//   - NUM_CHECKS: %d
	// ================================================================================
	CommandLine cl;

	// Read hostgroups from environment (set by infra .env), default to 1200/1201 for legacy-binlog
	const char* whg_env = getenv("BINLOG_WHG");
	const char* rhg_env = getenv("BINLOG_RHG");
	if (whg_env) WHG = std::stoul(whg_env);
	if (rhg_env) RHG = std::stoul(rhg_env);

	// Print test configuration for debugging
	fprintf(stderr, "\n");
	fprintf(stderr, "================================================================================\n");
	fprintf(stderr, "TEST: test_binlog_reader-t - GTID Consistency Test\n");
	fprintf(stderr, "================================================================================\n");
	fprintf(stderr, "Test Purpose: Verify ProxySQL integration with proxysql_mysqlbinlog for GTID consistency\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "CONNECTION SETTINGS:\n");
	fprintf(stderr, "  ProxySQL Host (MySQL): %s\n", cl.host ? cl.host : "(null)");
	fprintf(stderr, "  ProxySQL Port (MySQL): %d\n", cl.port);
	fprintf(stderr, "  ProxySQL Host (Admin): %s\n", cl.host ? cl.host : "(null)");
	fprintf(stderr, "  ProxySQL Port (Admin): %d\n", cl.admin_port);
	fprintf(stderr, "\n");
	fprintf(stderr, "CREDENTIALS (Test-only, hardcoded):\n");
	fprintf(stderr, "  MySQL User: sbtest8 / sbtest8\n");
	fprintf(stderr, "  Admin User: %s / %s\n",
		cl.admin_username ? cl.admin_username : "(null)",
		cl.admin_password ? "[REDACTED]" : "(null)");
	fprintf(stderr, "\n");
	fprintf(stderr, "TEST CONSTANTS:\n");
	fprintf(stderr, "  MAX_FAILURE_PCT: %.1f%%\n", MAX_FAILURE_PCT);
	fprintf(stderr, "  NUM_ROWS: %d\n", NUM_ROWS);
	fprintf(stderr, "  NUM_CHECKS: %d\n", NUM_CHECKS);
	fprintf(stderr, "\n");
	fprintf(stderr, "ENVIRONMENT VARIABLES:\n");
	fprintf(stderr, "  TAP_HOST: %s\n", getenv("TAP_HOST") ? getenv("TAP_HOST") : "(not set)");
	fprintf(stderr, "  TAP_PORT: %s\n", getenv("TAP_PORT") ? getenv("TAP_PORT") : "(not set)");
	fprintf(stderr, "  TAP_ADMINPORT: %s\n", getenv("TAP_ADMINPORT") ? getenv("TAP_ADMINPORT") : "(not set)");
	fprintf(stderr, "================================================================================\n");
	fprintf(stderr, "\n");

	if (cl.getEnv()) {
		fprintf(stderr, "ERROR: Failed to get the required environmental variables.\n");
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	fprintf(stderr, "Environment variables loaded successfully.\n");
	fprintf(stderr, "  cl.host: %s\n", cl.host ? cl.host : "(null)");
	fprintf(stderr, "  cl.port: %d\n", cl.port);
	fprintf(stderr, "  cl.admin_port: %d\n", cl.admin_port);
	fprintf(stderr, "\n");

	bool stop_on_failure = false;

	if (argc == 2) {
		if (string { argv[1] } == "stop_on_failure") { stop_on_failure = true; }
	}

	if (stop_on_failure) {
		fprintf(stderr, "Mode: stop_on_failure enabled\n");
		plan(0);
	} else {
		fprintf(stderr, "Mode: Normal test execution, planned tests: 3\n");
		plan(3);
	}

	fprintf(stderr, "\n");
	fprintf(stderr, "Initializing MySQL connections...\n");

	MYSQL* proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	// Both handles are initialized above. Close whichever succeeded so a
	// failure on one side doesn't leak the other. The cleanup: label below
	// can't be reached via goto from here because C++ forbids jumping past
	// the non-trivial std::vector<> initializations farther down in main().
	if (proxysql_mysql == NULL) {
		fprintf(stderr, "FATAL: mysql_init() failed for proxysql_mysql connection\n");
		if (proxysql_admin != NULL) { mysql_close(proxysql_admin); }
		return EXIT_FAILURE;
	}
	if (proxysql_admin == NULL) {
		fprintf(stderr, "FATAL: mysql_init() failed for proxysql_admin connection\n");
		mysql_close(proxysql_mysql);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "MySQL handles initialized successfully.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Attempting to connect to ProxySQL MySQL interface...\n");
	fprintf(stderr, "  Connection parameters:\n");
	fprintf(stderr, "    Host: %s\n", cl.host ? cl.host : "(null)");
	fprintf(stderr, "    User: sbtest8\n");
	fprintf(stderr, "    Password: sbtest8\n");
	fprintf(stderr, "    Port: %d\n", cl.port);
	fprintf(stderr, "\n");

	if (!mysql_real_connect(proxysql_mysql, cl.host, "sbtest8", "sbtest8", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "\n");
		fprintf(stderr, "================================================================================\n");
		fprintf(stderr, "CONNECTION FAILED: Unable to connect to ProxySQL MySQL interface\n");
		fprintf(stderr, "================================================================================\n");
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		fprintf(stderr, "\n");
		fprintf(stderr, "DIAGNOSTIC INFORMATION:\n");
		fprintf(stderr, "  Error indicates that user 'sbtest8' could not authenticate.\n");
		fprintf(stderr, "  Possible causes:\n");
		fprintf(stderr, "    1. User 'sbtest8' is not configured in mysql_users table\n");
		fprintf(stderr, "    2. Password mismatch (expected: 'sbtest8')\n");
		fprintf(stderr, "    3. User exists but is not loaded to runtime\n");
		fprintf(stderr, "    4. ProxySQL cannot reach backend MySQL server\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "TROUBLESHOOTING STEPS:\n");
		fprintf(stderr, "  1. Check mysql_users table: SELECT * FROM mysql_users WHERE username='sbtest8';\n");
		fprintf(stderr, "  2. Verify user is loaded to runtime: SELECT * FROM runtime_mysql_users WHERE username='sbtest8';\n");
		fprintf(stderr, "  3. Check if sbtest8 user exists on backend MySQL servers\n");
		fprintf(stderr, "================================================================================\n");
		mysql_close(proxysql_mysql);
		mysql_close(proxysql_admin);
		return EXIT_FAILURE;
	}
	fprintf(stderr, "SUCCESS: Connected to ProxySQL MySQL interface as sbtest8\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "Attempting to connect to ProxySQL Admin interface...\n");
	fprintf(stderr, "  Connection parameters:\n");
	fprintf(stderr, "    Host: %s\n", cl.host ? cl.host : "(null)");
	fprintf(stderr, "    User: %s\n", cl.admin_username ? cl.admin_username : "(null)");
	fprintf(stderr, "    Port: %d\n", cl.admin_port);
	fprintf(stderr, "\n");

	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "\n");
		fprintf(stderr, "================================================================================\n");
		fprintf(stderr, "CONNECTION FAILED: Unable to connect to ProxySQL Admin interface\n");
		fprintf(stderr, "================================================================================\n");
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		fprintf(stderr, "\n");
		mysql_close(proxysql_mysql);
		mysql_close(proxysql_admin);
		return EXIT_FAILURE;
	}
	fprintf(stderr, "SUCCESS: Connected to ProxySQL Admin interface\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "================================================================================\n");
	fprintf(stderr, "All connections established successfully. Starting test execution...\n");
	fprintf(stderr, "================================================================================\n");
	fprintf(stderr, "\n");

	// Create GTID-based query rules for sbtest8
	// Use rule_ids 100-102 to avoid overwriting rules set by calling tests
	// (e.g. test_binlog_reader_uses_previous_hostgroup-t sets rule_id=1 for port-based routing
	// that must survive so connections are tracked in the expected hostgroup)
	{
		string query;
		query = "DELETE FROM mysql_query_rules WHERE rule_id IN (100,101,102) OR username='sbtest8'";
		MYSQL_QUERY(proxysql_admin, query.c_str());
		mysql_free_result(mysql_store_result(proxysql_admin));

		query = "INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) "
			"VALUES (100,1,'sbtest8','^SELECT.*FOR UPDATE'," + std::to_string(WHG) + ",1,null,'test_binlog_reader-t')";
		MYSQL_QUERY(proxysql_admin, query.c_str());
		mysql_free_result(mysql_store_result(proxysql_admin));

		query = "INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) "
			"VALUES (101,1,'sbtest8','^SELECT'," + std::to_string(RHG) + ",1," + std::to_string(WHG) + ",'test_binlog_reader-t')";
		MYSQL_QUERY(proxysql_admin, query.c_str());
		mysql_free_result(mysql_store_result(proxysql_admin));

		query = "INSERT INTO mysql_query_rules (rule_id,active,username,match_digest,destination_hostgroup,apply,gtid_from_hostgroup,comment) "
			"VALUES (102,1,'sbtest8','.*'," + std::to_string(WHG) + ",1,null,'test_binlog_reader-t')";
		MYSQL_QUERY(proxysql_admin, query.c_str());
		mysql_free_result(mysql_store_result(proxysql_admin));

		query = "LOAD MYSQL QUERY RULES TO RUNTIME";
		MYSQL_QUERY(proxysql_admin, query.c_str());
		mysql_free_result(mysql_store_result(proxysql_admin));
		fprintf(stderr, "GTID query rules created for sbtest8 (WHG=%d, RHG=%d)\n", WHG, RHG);
	}

	MYSQL_QUERY_T(proxysql_admin, "SET mysql-session_track_variables=0");
	MYSQL_QUERY_T(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	vector<pair<uint32_t, mysql_res_row>> failed_rows {};
	vector<mysql_res_row> reader_1_read {};
	vector<mysql_res_row> reader_2_read {};

	// Reset connection pool stats
	int rc = mysql_query(proxysql_admin, "SELECT * FROM stats.stats_mysql_connection_pool_reset");
	if (rc != EXIT_SUCCESS) { goto cleanup; }
	mysql_free_result(mysql_store_result(proxysql_admin));

	// Create testing tables
	rc = create_testing_tables(proxysql_mysql);
	if (rc != EXIT_SUCCESS) { goto cleanup; }

	rc = insert_random_data(proxysql_mysql, NUM_ROWS);
	if (rc != EXIT_SUCCESS) { goto cleanup; }

	for (uint32_t i = 0; i < NUM_CHECKS; i++) {
		rc = perform_update(proxysql_mysql, NUM_ROWS);
		if (rc != EXIT_SUCCESS) { goto cleanup; }

		// Previously a mysql_store_result() was issued on proxysql_admin here
		// with no corresponding preceding query; the resulting MYSQL_RES was
		// always NULL and the extracted vector was dead code. Removed.

		int r_row = rand() % static_cast<int>(NUM_ROWS);
		if (r_row == 0) { r_row = 1; }

		string s_query {};
		string_format("SELECT * FROM test.gtid_test WHERE id=%d", s_query, r_row);

		rc = mysql_query(proxysql_mysql, s_query.c_str());
		if (rc != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			goto cleanup;
		}

		MYSQL_RES* my_s_res = mysql_store_result(proxysql_mysql);
		vector<mysql_res_row> res_row = extract_mysql_rows(my_s_res);
		mysql_free_result(my_s_res);

		if (res_row.empty() || res_row[0].size() < 2) {
			fprintf(stderr, "File %s, line %d, Error: unexpected result set shape (rows=%zu)\n",
				__FILE__, __LINE__, res_row.size());
			goto cleanup;
		}
		int cur_a = static_cast<int>(std::stol(res_row[0][1]));

		if (cur_a != r_row + i) {
			failed_rows.push_back({r_row + i, res_row[0] });

			if (stop_on_failure) {
				break;
			}
		}
	}

	{
		if (stop_on_failure == 0) {
			check_gitd_tracking(cl, proxysql_mysql, proxysql_admin);

			const double pct_fail_rate = static_cast<double>(failed_rows.size()) * 100 / static_cast<double>(NUM_CHECKS);
			ok(
				pct_fail_rate < MAX_FAILURE_PCT,
				"Detected dirty reads shouldn't surpass the expected threshold: {"
					" failed_rows: %ld, exp_fail_rate: %lf, act_fail_rate: %lf }",
				failed_rows.size(), MAX_FAILURE_PCT, pct_fail_rate
			);
		} else {
			string s_failed_rows = std::accumulate(failed_rows.begin(), failed_rows.end(), string { "\n" },
				[](const string& s, const pair<uint32_t, mysql_res_row>& row) -> string {
					return s + "{ exp_a: " + std::to_string(row.first) + ", row: " + json { row.second }.dump() + " }\n";
				}
			);

			diag("Dirty reads found for rows: %s", s_failed_rows.c_str());
		}
	}

cleanup:

	mysql_close(proxysql_mysql);
	mysql_close(proxysql_admin);

	return exit_status();
}
