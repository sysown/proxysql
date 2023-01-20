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

#include <mysql.h>
#include <mysql/mysqld_error.h>
#include <json.hpp>

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
	MYSQL_QUERY(mysql_server, "CREATE DATABASE IF NOT EXISTS binlog_db");
	MYSQL_QUERY(mysql_server, "DROP TABLE IF EXISTS binlog_db.gtid_test");

	MYSQL_QUERY(
		mysql_server,
		"CREATE TABLE IF NOT EXISTS binlog_db.gtid_test ("
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
	int rnd_a = rand() % 1000;
	string rnd_c = random_string(rand() % 100 + 5);
	string rnd_pad = random_string(rand() % 50 + 5);

	for (uint32_t i = 0; i < rows; i++) {
		string update_query {};
		string_format(
			"INSERT INTO binlog_db.gtid_test (a, c, pad) VALUES ('%d', '%s', '%s')", update_query,
			i, rnd_c.c_str(), rnd_pad.c_str()
		);
		MYSQL_QUERY(proxysql_mysql, update_query.c_str());
	}

	return EXIT_SUCCESS;
}

int perform_update(MYSQL* proxysql_mysql, uint32_t rows) {
	int rnd_a = rand() % 1000;
	string rnd_c = random_string(rand() % 100 + 5);
	string rnd_pad = random_string(rand() % 60 + 5);

	string query { "UPDATE binlog_db.gtid_test SET a=a+1, c=REVERSE(c)" };
	MYSQL_QUERY(proxysql_mysql, query.c_str());

	return EXIT_SUCCESS;
}

const double MAX_FAILURE_PCT = 15.0;
const uint32_t NUM_ROWS = 3000;
const uint32_t NUM_CHECKS = 500;

map<uint32_t, pair<uint32_t,uint32_t>> extract_hosgtroups_stats(const vector<mysql_res_row>& conn_pool_stats) {
	uint32_t hg_50_queries = 0;
	uint32_t hg_50_sync_queries = 0;
	uint32_t hg_60_queries = 0;
	uint32_t hg_60_sync_queries = 0;

	for (const auto& conn_pool_stats_row : conn_pool_stats) {
		if (conn_pool_stats_row.size() < 3) {
			const char* msg = "Invalid result received from 'stats.stats_mysql_connection_pool'";
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, msg);
			return {};
		}

		const uint32_t hg = std::stol(conn_pool_stats_row[0]);
		const uint32_t queries = std::stol(conn_pool_stats_row[1]);
		const uint32_t queries_gtid_sync = std::stol(conn_pool_stats_row[2]);

		if (hg == 50) {
			hg_50_queries += queries;
			hg_50_sync_queries += queries_gtid_sync;
		} else if (hg == 60) {
			hg_60_queries += queries;
			hg_60_sync_queries += queries_gtid_sync;
		}
	}

	return { { 50, { hg_50_queries, hg_50_sync_queries } }, { 60, { hg_60_queries, hg_60_sync_queries } } };
}

int perform_rnd_selects(const CommandLine& cl, uint32_t NUM) {
	// Check connections only performing select doesn't contribute to GITD count
	MYSQL* select_conn = mysql_init(NULL);

	if (!mysql_real_connect(select_conn, cl.host, "sbtest7", "sbtest7", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(select_conn));
		return EXIT_FAILURE;
	}

	for (uint32_t i = 0; i < NUM; i++) {
		int r_row = rand() % NUM_ROWS;
		if (r_row == 0) { r_row = 1; }

		string s_query {};
		string_format("SELECT * FROM binlog_db.gtid_test WHERE id=%d", s_query, r_row);

		// Perform the select and ignore the result
		int rc = mysql_query(select_conn, s_query.c_str());
		if (rc != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(select_conn));
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
	uint32_t hg_50_queries = hg_stats.at(50).first;
	uint32_t hg_50_sync_queries = hg_stats.at(50).second;;
	uint32_t hg_60_queries = hg_stats.at(60).first;
	uint32_t hg_60_sync_queries = hg_stats.at(60).second;;

	uint32_t hg_50_exp_queries =
		3 +            // Database creation + Table DROP + Table creation
		NUM_ROWS +     // Initial data load
		NUM_CHECKS;    // Updates (matching number of checks)
	uint32_t hg_50_exp_sync_queries = NUM_CHECKS - 1;

	bool hg_50_checks = hg_50_exp_queries == hg_50_queries && hg_50_sync_queries == hg_50_exp_sync_queries;
	bool hg_60_checks = hg_60_queries == NUM_CHECKS && hg_60_sync_queries == NUM_CHECKS;

	ok(
		hg_50_checks && hg_60_checks,
		"GTID based query routing: {"
			" hg_50: { exp_queries: %d, act_queries: %d, exp_sync_queries: %d, act_sync_queries: %d },"
			" hg_60: { exp_queries: %d, act_queries: %d, exp_sync_queries: %d, act_sync_queries: %d }"
		" }",
		hg_50_exp_queries, hg_50_queries, hg_50_exp_sync_queries, hg_50_sync_queries,
		NUM_CHECKS, hg_60_queries, NUM_CHECKS, hg_60_queries
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
	hg_50_queries = hg_stats.at(50).first;
	hg_50_sync_queries = hg_stats.at(50).second;;
	hg_60_queries = hg_stats.at(60).first;
	hg_60_sync_queries = hg_stats.at(60).second;;

	uint32_t hg_60_exp_queries = NUM_CHECKS / 5;
	ok(
		hg_50_queries == 0 && hg_50_sync_queries == 0 && hg_60_queries == hg_60_exp_queries && hg_60_sync_queries == 0,
		"Queries should only be executed in 'HG 60' and no GTID sync should take place: {"
		" hg_50: { exp_queries: 0, act_queries: %d, exp_sync_queries: 0, act_sync_queries: %d },"
		" hg_60: { exp_queries: %d, act_queries: %d, exp_sync_queries: 0, act_sync_queries: %d },"
		" }",
		hg_50_queries, hg_50_sync_queries, hg_60_exp_queries, hg_60_queries, hg_60_sync_queries
	);

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	bool stop_on_failure = false;

	if (argc == 2) {
		if (string { argv[1] } == "stop_on_failure") { stop_on_failure = true; }
	}

	if (stop_on_failure) {
		plan(0);
	} else {
		plan(3);
	}

	MYSQL* proxysql_mysql = mysql_init(NULL);
	MYSQL* proxysql_admin = mysql_init(NULL);

	if (!mysql_real_connect(proxysql_mysql, cl.host, "sbtest7", "sbtest7", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
		return EXIT_FAILURE;
	}
	if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
		return EXIT_FAILURE;
	}

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

		MYSQL_RES* my_res = mysql_store_result(proxysql_admin);
		vector<mysql_res_row> pre_select_rows = extract_mysql_rows(my_res);
		mysql_free_result(my_res);

		int r_row = rand() % NUM_ROWS;
		if (r_row == 0) { r_row = 1; }

		string s_query {};
		string_format("SELECT * FROM binlog_db.gtid_test WHERE id=%d", s_query, r_row);

		// Perform the select and ignore the result
		rc = mysql_query(proxysql_mysql, s_query.c_str());
		if (rc != EXIT_SUCCESS) {
			fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_mysql));
			goto cleanup;
		}

		MYSQL_RES* my_s_res = mysql_store_result(proxysql_mysql);
		vector<mysql_res_row> res_row = extract_mysql_rows(my_s_res);
		mysql_free_result(my_s_res);

		int cur_a = std::stol(res_row[0][1]);

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

			const double pct_fail_rate = failed_rows.size() * 100 / static_cast<double>(NUM_CHECKS);
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
