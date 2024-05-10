/**
 * @file test_query_rules_fast_routing_algorithm-t.cpp
 * @brief This test performs the following checks:
 *   - That multiple 'rules_fast_routing' are being properly evaluated.
 *   - That 'mysql-query_rules_fast_routing_algorithm' properly controls from which hashmaps the query
 *     rules are searched.
 *   - That used memory increases/decreases as expected depending on the value selected for
 *     'mysql-query_rules_fast_routing_algorithm'.
 */

#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <fstream>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

#include "json.hpp"

using std::pair;
using std::string;
using nlohmann::json;
using std::fstream;
using std::vector;

// Used for 'extract_module_host_port'
#include "modules_server_test.h"

void parse_result_json_column(MYSQL_RES *result, json& j) {
	if(!result) return;
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(result))) {
		j = json::parse(row[0]);
	}
}

int extract_internal_session(MYSQL* proxy, nlohmann::json& j_internal_session) {
	MYSQL_QUERY_T(proxy, "PROXYSQL INTERNAL SESSION");
	MYSQL_RES* myres = mysql_store_result(proxy);
	parse_result_json_column(myres, j_internal_session);
	mysql_free_result(myres);

	return EXIT_SUCCESS;
}

int get_query_int_res(MYSQL* admin, const string& q, int& val) {
	MYSQL_QUERY_T(admin, q.c_str());
	MYSQL_RES* myres = mysql_store_result(admin);
	MYSQL_ROW myrow = mysql_fetch_row(myres);

	int res = EXIT_FAILURE;

	if (myrow && myrow[0]) {
		char* p_end = nullptr;
		val = std::strtol(myrow[0], &p_end, 10);

		if (p_end == myrow[0]) {
			diag("Failed to parse query result as 'int' - res: %s, query: %s", myrow[0], q.c_str());
		} else {
			res = EXIT_SUCCESS;
		}
	} else {
		diag("Received empty result for query `%s`", q.c_str());
	}

	mysql_free_result(myres);

	return res;
}

int extract_sess_qpo_dest_hg(MYSQL* proxy) {
	json j_internal_session {};
	int j_err = extract_internal_session(proxy, j_internal_session);
	if (j_err) {
		diag("Failed to extract and parse result from 'PROXYSQL INTERNAL SESSION'");
		return -2;
	}

	int dest_hg = -2;
	try {
		dest_hg = j_internal_session["qpo"]["destination_hostgroup"];
	} catch (const std::exception& e) {
		diag("Processing of 'PROXYSQL INTERNAL SESSION' failed with exc: %s", e.what());
		return -2;
	}

	return dest_hg;
}

int check_fast_routing_rules(MYSQL* proxy, uint32_t rng_init, uint32_t rng_end) {
	for (uint32_t i = rng_init; i < rng_end; i += 2) {
//		const string schema { "randomschemaname" + std::to_string(i) };
		const string schema { "test" + std::to_string(i) };

		diag("Changing schema to '%s'", schema.c_str());
		if (mysql_select_db(proxy, schema.c_str())) {
			fprintf(stdout, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
			return EXIT_FAILURE;
		}

		diag("Issuing simple 'SELECT 1' to trigger WRITER rule for '%s'", schema.c_str());
		MYSQL_QUERY_T(proxy, "SELECT 1");
		mysql_free_result(mysql_store_result(proxy));

		int dest_hg = extract_sess_qpo_dest_hg(proxy);
		if (dest_hg == -2) {
			return EXIT_FAILURE;
		}

		ok(i == dest_hg, "Destination hostgroup matches expected - Exp: %d, Act: %d", i, dest_hg);

		diag("Issuing simple 'SELECT 2' to trigger READER rule for '%s'", schema.c_str());
		MYSQL_QUERY_T(proxy, "SELECT 2");
		mysql_free_result(mysql_store_result(proxy));

		dest_hg = extract_sess_qpo_dest_hg(proxy);
		if (dest_hg == -2) {
			return EXIT_FAILURE;
		}

		ok(i + 1 == dest_hg, "Destination hostgroup matches expected - Exp: %d, Act: %d", i + 1, dest_hg);
	}

	return EXIT_SUCCESS;
};

string get_last_debug_log_id(sqlite3* sq3_db) {
	sq3_res_t last_id_res { sqlite3_execute_stmt(sq3_db, "SELECT id FROM debug_log ORDER BY id DESC limit 1") };
	const vector<sq3_row_t>& last_id_rows { std::get<SQ3_RES_T::SQ3_ROWS>(last_id_res) };
	if (last_id_rows.empty()) {
		diag("Empty resultset from 'proxysql_debug.db', database failed to be updated");
		return {};
	}

	return last_id_rows[0][0];
}

int create_mysql_servers_range(
	const CommandLine& cl, MYSQL* admin, const pair<string,int>& host_port, uint32_t rng_init, uint32_t rng_end
) {
	const string init { std::to_string(rng_init) };
	const string end { std::to_string(rng_end) };

	MYSQL_QUERY_T(admin, ("DELETE FROM mysql_servers WHERE hostgroup_id BETWEEN " + init + " AND " + end).c_str());

	for (uint32_t i = rng_init; i < rng_end; i += 2) {
		std::string q = "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES ";
		q += "(" + std::to_string(i)   + ",'" + host_port.first + "'," + std::to_string(host_port.second) + ")";
		q += ",";
		q += "(" + std::to_string(i+1) + ",'" + host_port.first + "'," + std::to_string(host_port.second) + ")";
		MYSQL_QUERY(admin, q.c_str());
	}

	return EXIT_SUCCESS;
};

int create_fast_routing_rules_range(
	const CommandLine& cl, MYSQL* admin, const pair<string,int>& host_port, uint32_t rng_init, uint32_t rng_end
) {
	const string init { std::to_string(rng_init) };
	const string end { std::to_string(rng_end) };

	MYSQL_QUERY_T(admin, ("DELETE FROM mysql_query_rules_fast_routing WHERE destination_hostgroup BETWEEN " + init + " AND " + end).c_str());

	for (uint32_t i = rng_init; i < rng_end; i += 2) {
//		const string schema { "randomschemaname" + std::to_string(i) + "" };
		const string schema { "test" + std::to_string(i) + "" };
		const string user { cl.username };
		string q = "INSERT INTO mysql_query_rules_fast_routing (username, schemaname, flagIN, destination_hostgroup, comment) VALUES ";

		q += "('" + user + "', '" + schema + "' , 0, " + std::to_string(i)   + ", 'writer" + std::to_string(i) +   "'),";
		q += "('" + user + "', '" + schema + "' , 1, " + std::to_string(i+1) + ", 'reader" + std::to_string(i+1) + "')";

		MYSQL_QUERY(admin, q.c_str());
	}

	return EXIT_SUCCESS;
};

int sq3_get_matching_msg_entries(sqlite3* db, const string& query_regex, const string& id) {
	string init_db_query {
		"SELECT COUNT() FROM debug_log WHERE message LIKE '%" + query_regex + "%' AND id > " + id
	};
	sq3_res_t sq3_entries_res { sqlite3_execute_stmt(db, init_db_query) };
	const string& sq3_err { std::get<SQ3_RES_T::SQ3_ERR>(sq3_entries_res) };
	if (!sq3_err.empty()) {
		diag("Query failed to be executed in SQLite3 - query: `%s`, err: `%s`", init_db_query.c_str(), sq3_err.c_str());
		return EXIT_FAILURE;
	}

	const vector<sq3_row_t>& sq3_rows { std::get<SQ3_RES_T::SQ3_ROWS>(sq3_entries_res) };
	int32_t matching_rows = std::atoi(sq3_rows[0][0].c_str());

	return matching_rows;
};

int test_fast_routing_algorithm(
	const CommandLine& cl, MYSQL* admin, MYSQL* proxy, const pair<string,int>& host_port, fstream& errlog,
	int init_algo, int new_algo
) {
	uint32_t rng_init = 1000;
	uint32_t rng_end = 1020;
	const char query_rules_mem_stats_query[] {
		"SELECT variable_value FROM stats_memory_metrics WHERE variable_name='mysql_query_rules_memory'"
	};

	// Enable Admin debug, set debug_output to log and DB, and increase verbosity for Query_Processor
	MYSQL_QUERY_T(admin, "SET admin-debug=1");
	MYSQL_QUERY_T(admin, "SET admin-debug_output=3");
	MYSQL_QUERY_T(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	MYSQL_QUERY_T(admin, "UPDATE debug_levels SET verbosity=7 WHERE module='debug_mysql_query_processor'");
	// If there is a generic debug filter (line==0) on Query_Processor.cpp , process_mysql_query() , disable it.
	// If the filter was present it will be automatically recreated by the tester.
	MYSQL_QUERY_T(admin, "DELETE FROM debug_filters WHERE filename='Query_Processor.cpp' AND line=0 AND funct='process_mysql_query'");
	MYSQL_QUERY_T(admin, "LOAD DEBUG TO RUNTIME");

	// Open the SQLite3 db for debugging
	const string db_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql_debug.db" };
	sqlite3* sq3_db = nullptr;

	int odb_err = open_sqlite3_db(db_path, &sq3_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (odb_err) { return EXIT_FAILURE; }
	int c_err = create_mysql_servers_range(cl, admin, host_port, rng_init, rng_end);
	if (c_err) { return EXIT_FAILURE; }
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	printf("\n");
	diag("Testing 'query_rules_fast_routing_algorithm=%d'", init_algo);
	MYSQL_QUERY_T(admin, ("SET mysql-query_rules_fast_routing_algorithm=" + std::to_string(init_algo)).c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Always cleanup the rules before the test to get proper memory usage diff
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules_fast_routing");
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	int init_rules_mem_stats = -1;
	int get_mem_stats_err = get_query_int_res(admin, query_rules_mem_stats_query, init_rules_mem_stats);
	if (get_mem_stats_err) { return EXIT_FAILURE; }
	diag("Initial 'mysql_query_rules_memory' of '%d'", init_rules_mem_stats);

	// Check that fast_routing rules are being properly triggered
	c_err = create_fast_routing_rules_range(cl, admin, host_port, rng_init, rng_end);
	if (c_err) { return EXIT_FAILURE; }
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	usleep(1000*1000);

	// Seek end of file for error log
	errlog.seekg(0, std::ios::end);
	// Get current last id from debug db
	string last_debug_log_id { get_last_debug_log_id(sq3_db) };
	if (last_debug_log_id.empty()) { return EXIT_FAILURE; }

	// Check that fast_routing rules are properly working for the defined range
	check_fast_routing_rules(proxy, rng_init, rng_end);

	// Give some time for the error log and SQLite3 to be written
	usleep(100*1000);

	const string init_algo_scope { init_algo == 1 ? "thread-local" : "global" };
	const string init_search_regex { "Searching " + init_algo_scope + " 'rules_fast_routing' hashmap" };
	vector<line_match_t> matched_lines { get_matching_lines(errlog, init_search_regex) };

	ok(
		matched_lines.size() == rng_end - rng_init,
		"Number of '%s' searchs in error log should match issued queries - Exp: %d, Act: %ld",
		init_algo_scope.c_str(), rng_end - rng_init, matched_lines.size()
	);

	const string sq3_query_regex { "Searching " + init_algo_scope + " ''rules_fast_routing'' hashmap" };
	int matching_rows = sq3_get_matching_msg_entries(sq3_db, sq3_query_regex, last_debug_log_id);

	ok(
		matching_rows == rng_end - rng_init,
		"Number of '%s' entries in SQLite3 'debug_log' should match issued queries - Exp: %d, Act: %ld",
		init_algo_scope.c_str(), rng_end - rng_init, matched_lines.size()
	);
	printf("\n");

	int old_mem_stats = -1;
	get_mem_stats_err = get_query_int_res(admin, query_rules_mem_stats_query, old_mem_stats);
	if (get_mem_stats_err) { return EXIT_FAILURE; }

	// Changing the algorithm shouldn't have any effect
	diag("Testing 'query_rules_fast_routing_algorithm=%d'", new_algo);
	MYSQL_QUERY_T(admin, ("SET mysql-query_rules_fast_routing_algorithm=" + std::to_string(new_algo)).c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	usleep(1000*1000);

	// Seek end of file for error log
	errlog.seekg(0, std::ios::end);
	// Get current last id from debug db
	last_debug_log_id = get_last_debug_log_id(sq3_db);
	if (last_debug_log_id.empty()) { return EXIT_FAILURE; }

	diag("Search should still be performed 'per-thread'. Only variable has changed.");
	check_fast_routing_rules(proxy, rng_init, rng_end);

	// Give some time for the error log to be written
	usleep(100*1000);

	matched_lines = get_matching_lines(errlog, init_search_regex);

	ok(
		matching_rows == rng_end - rng_init,
		"Number of '%s' entries in SQLite3 'debug_log' should match issued queries - Exp: %d, Act: %ld",
		init_algo_scope.c_str(), rng_end - rng_init, matched_lines.size()
	);

	matching_rows = sq3_get_matching_msg_entries(sq3_db, sq3_query_regex, last_debug_log_id);

	ok(
		matched_lines.size() == rng_end - rng_init,
		"Number of 'thread-local' searchs in error log should match issued queries - Exp: %d, Act: %ld",
		rng_end - rng_init, matched_lines.size()
	);

	int new_mem_stats = -1;
	get_mem_stats_err = get_query_int_res(admin, query_rules_mem_stats_query, new_mem_stats);
	if (get_mem_stats_err) { return EXIT_FAILURE; }

	diag("Memory SHOULDN'T have changed just because of a variable change");
	ok(
		old_mem_stats - init_rules_mem_stats == new_mem_stats - init_rules_mem_stats,
		"Memory stats shouldn't increase just by the variable change - old: %d, new: %d",
		old_mem_stats - init_rules_mem_stats, new_mem_stats - init_rules_mem_stats
	);
	printf("\n");

	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	diag("Search should now be using the per thread-maps");

	// Seek end of file for error log
	errlog.seekg(0, std::ios::end);
	check_fast_routing_rules(proxy, rng_init, rng_end);

	// Give some time for the error log to be written
	usleep(100*1000);

	const string new_algo_scope { new_algo == 1 ? "thread-local" : "global" };
	const string new_search_regex { "Searching " + new_algo_scope + " 'rules_fast_routing' hashmap" };
	vector<line_match_t> new_matched_lines { get_matching_lines(errlog, new_search_regex) };

	ok(
		new_matched_lines.size() == rng_end - rng_init,
		"Number of '%s' searchs in error log should match issued queries - Exp: %d, Act: %ld",
		new_algo_scope.c_str(), rng_end - rng_init, new_matched_lines.size()
	);

	const string new_sq3_query_regex { "Searching " + new_algo_scope + " ''rules_fast_routing'' hashmap" };
	int new_matching_rows = sq3_get_matching_msg_entries(sq3_db, sq3_query_regex, last_debug_log_id);

	ok(
		new_matching_rows == rng_end - rng_init,
		"Number of '%s' entries in SQLite3 'debug_log' should match issued queries - Exp: %d, Act: %d",
		new_algo_scope.c_str(), rng_end - rng_init, new_matching_rows
	);

	get_mem_stats_err = get_query_int_res(admin, query_rules_mem_stats_query, new_mem_stats);
	if (get_mem_stats_err) { return EXIT_FAILURE; }

	bool mem_check_res = false;
	string exp_change { "" };

	if (init_algo == 1 && new_algo == 2) {
		mem_check_res = (old_mem_stats - init_rules_mem_stats) > (new_mem_stats - init_rules_mem_stats);
		exp_change = "decrease";
	} else if (init_algo == 2 && new_algo == 1) {
		mem_check_res = (old_mem_stats - init_rules_mem_stats) < (new_mem_stats - init_rules_mem_stats);
		exp_change = "increase";
	} else {
		mem_check_res = (old_mem_stats - init_rules_mem_stats) == (new_mem_stats - init_rules_mem_stats);
		exp_change = "not change";
	}

	ok(
		mem_check_res,
		"Memory stats should %s after 'LOAD MYSQL QUERY RULES TO RUNTIME' - old: %d, new: %d",
		exp_change.c_str(), (old_mem_stats - init_rules_mem_stats), (new_mem_stats - init_rules_mem_stats)
	);

	return EXIT_SUCCESS;
};

int main(int argc, char** argv) {
	// `5` logic checks + 20*3 checks per query rule, per test
	plan((8 + 20*3) * 2);

	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	MYSQL* admin = mysql_init(NULL);

	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	pair<string,int> host_port {};
	int host_port_err = extract_module_host_port(admin, "sqliteserver-mysql_ifaces", host_port);

	if (host_port_err) {
		goto cleanup;
	}

	MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules");
	MYSQL_QUERY_T(admin, "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, flagOUT, cache_ttl) VALUES (1,1,'^SELECT 1$', 0, 600000)");
	MYSQL_QUERY_T(admin, "INSERT INTO mysql_query_rules (rule_id, active, match_pattern, flagOUT, cache_ttl) VALUES (2,1,'^SELECT 2$', 1, 600000)");
	MYSQL_QUERY_T(admin, "DELETE FROM mysql_query_rules_fast_routing");
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	{
		const string f_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
		fstream errlog {};

		int of_err = open_file_and_seek_end(f_path, errlog);
		if (of_err) {
			diag("Failed to open ProxySQL log file. Aborting further testing...");
			goto cleanup;
		}

		int test_err = test_fast_routing_algorithm(cl, admin, proxy, host_port, errlog, 1, 2);
		if (test_err) { goto cleanup; }

		test_err = test_fast_routing_algorithm(cl, admin, proxy, host_port, errlog, 2, 1);
		if (test_err) { goto cleanup; }
	}

cleanup:

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
