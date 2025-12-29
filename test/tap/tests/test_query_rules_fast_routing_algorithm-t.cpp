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
#include <functional>
#include <thread>
#include <map>

#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

#include "json.hpp"

using nlohmann::json;

using std::map;
using std::pair;
using std::string;
using std::fstream;
using std::function;
using std::vector;

// Used for 'extract_module_host_port'
#include "modules_server_test.h"

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
	try {
		j_internal_session = fetch_internal_session(proxy);
	} catch (const std::exception& e) {
		diag("Failed to fetch 'PROXYSQL INTERNAL SESSION'   exception=\"%s\"", e.what());
		return -2;
	}

	int dest_hg = -2;
	try {
		dest_hg = j_internal_session["qpo"]["destination_hostgroup"];
		diag("Session information   thread=%s", j_internal_session["thread"].dump().c_str());
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
	const CommandLine& cl,
	MYSQL* admin,
	const pair<string,int>& host_port,
	uint32_t rng_init,
	uint32_t rng_end
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
	const CommandLine& cl, MYSQL* admin, uint32_t rng_init, uint32_t rng_end
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

const char q_query_rules_mem_stats[] {
	"SELECT variable_value FROM stats_memory_metrics WHERE variable_name='mysql_query_rules_memory'"
};
const char SELECT_LAST_DEBUG_ID[] { "SELECT id FROM debug_log ORDER BY id DESC limit 1" };

int check_fast_routing_rules(
	const CommandLine& cl,
	MYSQL* proxy,
	MYSQL* admin,
	uint32_t rng_init,
	uint32_t rng_end,
	const string& algo,
	fstream& errlog,
	sqlite3* sq3_db
) {
	// Seek end of file for error log
	errlog.seekg(0, std::ios::end);
	diag("Seek end of error log file   pos=%lu", size_t(errlog.tellg()));

	diag("Flush debug logs to ensure getting the latest id");
	MYSQL_QUERY_T(admin, "PROXYSQL FLUSH LOGS");

	diag("Getting last 'debug_log' entry id");
	ext_val_t<uint32_t> last_id { sq3_query_ext_val(sq3_db, SELECT_LAST_DEBUG_ID, uint32_t(0)) };
	CHECK_EXT_VAL(last_id);
	diag("Fetched last 'debug_log' entry id   id=%d", last_id.val);

	// Check that fast_routing rules are properly working for the defined range
	int rc = check_fast_routing_rules(proxy, rng_init, rng_end);
	if (rc) { return EXIT_FAILURE; }

	const string init_search_regex { "Searching " + algo + " 'rules_fast_routing' hashmap" };
	auto [insp_lines, matched_lines] { get_matching_lines(errlog, init_search_regex) };
	diag(
		"Inspected error log for matching lines   pos=%lu insp_lines=%ld match_lines=%ld regex=\"%s\"",
		size_t(errlog.tellg()), insp_lines, matched_lines.size(), init_search_regex.c_str()
	);

	ok(
		matched_lines.size() == rng_end - rng_init,
		"Number of '%s' entries in error log should match issued queries - Exp: %d, Act: %ld",
		algo.c_str(), rng_end - rng_init, matched_lines.size()
	);

	const function<pair<int,int>()> check_sq3_entries {
		[&] () -> pair<int,int> {
			const string dbg_msg {
				"Searching " + algo + " ''rules_fast_routing'' hashmap % schema=''test"
			};
			const string select_count {
				"SELECT COUNT() FROM debug_log WHERE"
					" id > " + _TO_S(last_id.val) + " AND message LIKE '%" + dbg_msg + "%'"
			};
			ext_val_t<int64_t> entries { sq3_query_ext_val(sq3_db, select_count, int64_t(-1))};
			if (entries.err) {
				const string err { get_ext_val_err(admin, entries) };
				diag("%s:%d: Query failed   err=\"%s\"", __func__, __LINE__, err.c_str());
				return { -1, 0 };
			}

			diag(
				"Checking matched entries   entries=%ld last_debug_log_id=%d query=\"%s\"",
				entries.val, last_id.val, select_count.c_str()
			);

			if (entries.val > 0) {
				return { entries.val == (rng_end - rng_init), entries.val };
			} else {
				return { entries.val, 0 };
			}
		}
	};

	diag("Flush debug logs before fetching expected entries");
	MYSQL_QUERY_T(admin, "PROXYSQL FLUSH LOGS");

	auto [wait_res, matching_rows] = wait_for_cond(check_sq3_entries, 1000*1000, 250*1000);
	if (wait_res != 0) { exit(1); }

	ok(
		wait_res == 0,
		"Number of '%s' entries in SQLite3 'debug_log' should match issued queries - Exp: %d, Act: %d",
		algo.c_str(), rng_end - rng_init, matching_rows
	);

	return EXIT_SUCCESS;
}

const string PROXYSQL_QLOG_DIR { get_env_str("REGULAR_INFRA_DATADIR", "/tmp/datadir") };

int threads_warmup(const CommandLine& cl, MYSQL* admin, sqlite3* sq3_db) {
	ext_val_t<int> mysql_threads {
		mysql_query_ext_val(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='mysql-threads'", 0
		)
	};
	CHECK_EXT_VAL(mysql_threads);

	const ext_val_t<string> qlog_fname {
		mysql_query_ext_val(admin, SELECT_RUNTIME_VAR"'mysql-eventslog_filename'", _S("query.log"))
	};
	CHECK_EXT_VAL(qlog_fname);
	const string PROXYSQL_AUDIT_LOG { PROXYSQL_QLOG_DIR + "/" + qlog_fname.str };

	diag("Flush debug logs to ensure getting the latest id");
	MYSQL_QUERY_T(admin, "PROXYSQL FLUSH LOGS");

	diag("Getting last 'debug_log' entry id");
	ext_val_t<uint32_t> last_id { sq3_query_ext_val(sq3_db, SELECT_LAST_DEBUG_ID, uint32_t(0)) };
	CHECK_EXT_VAL(last_id);
	diag("Fetched last 'debug_log' entry id   id=%d", last_id.val);

	int conns { find_min_elems(1.0 - pow(10, -6), mysql_threads.val) /* * 2 */ };
	double th_conns { ceil(double(conns) / mysql_threads.val) };

	diag(
		"Performing warm-up queries   queries=%d th_queries=%lf workers=%d",
		conns, th_conns, mysql_threads.val
	);
	vector<std::thread> workers {};

	pthread_barrier_t bar;
	pthread_barrier_init(&bar, NULL, mysql_threads.val);

	for (int i = 0; i < mysql_threads.val; i++) {
		workers.emplace_back(std::thread([&cl, th_conns, i, &bar] () {
			pthread_barrier_wait(&bar);

			const string th_id { to_string(std::this_thread::get_id()) };
			auto curtime = monotonic_time();
			diag("Worker starting warm-up conn   time=%lld thread_id=%s", curtime, th_id.c_str());

			for (int j = 0; j < th_conns; j++) {
				MYSQL* proxy = mysql_init(NULL);

				if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
					fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
					return EXIT_FAILURE;
				}

				const char* wup_query { rand() % 2 ?
					"SELECT /* thread_warmup-" __FILE__ " */ 1" :
					"SELECT /* thread_warmup-" __FILE__ " */ 2"
				};
				diag("Issuing query from worker   thread_id=%s query=\"%s\"", th_id.c_str(), wup_query);
				MYSQL_QUERY_T(proxy, wup_query);
				mysql_free_result(mysql_store_result(proxy));

				mysql_close(proxy);
			}

			return 0;
		}));
	}

	for (std::thread& w : workers) {
		w.join();
	}

	pthread_barrier_destroy(&bar);

	diag("Flush debug logs before fetching thread dist entries");
	MYSQL_QUERY_T(admin, "PROXYSQL FLUSH LOGS");

	const auto [_, matched_entries] {
		sq3_get_debug_entries(sq3_db,
			"id > " + _TO_S(last_id.val) + " AND file='MySQL_Session.cpp'"
			" AND message LIKE '%Processing received query%thread_warmup-" __FILE__ "%'"
		)
	};

	std::map<uint32_t, uint32_t> threads_ids {};

	for (const debug_entry_t& dbg_entry : matched_entries) {
		threads_ids[dbg_entry.thread] += 1;
	}

	diag("Thread query distribution:\n%s", nlohmann::json(threads_ids).dump(4).c_str());

	ok(
		threads_ids.size() == mysql_threads.val,
		"Each thread processed at least one warm-up query   threads_ids=%ld mysql_threads=%d",
		threads_ids.size(), mysql_threads.val
	);

	return EXIT_FAILURE;
}

int test_fast_routing_algorithm(
	const CommandLine& cl,
	MYSQL* admin,
	MYSQL* proxy,
	const pair<string,int>& host_port,
	fstream& errlog,
	int init_algo, int new_algo
) {
	uint32_t rng_init = 1000;
	uint32_t rng_end = 1020;

	// Enable Admin debug, set debug_output to log and DB, and increase verbosity for Query_Processor
	MYSQL_QUERY_T(admin, "SET admin-debug=1");
	MYSQL_QUERY_T(admin, "SET admin-debug_output=3");
	MYSQL_QUERY_T(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	MYSQL_QUERY_T(admin, "UPDATE debug_levels SET verbosity=7 WHERE module='debug_mysql_query_processor'");

	// Remove **generic debug filters** (line==0) relevant for the test.
	MYSQL_QUERY_T(admin, "DELETE FROM debug_filters WHERE filename='Query_Processor.cpp' AND line=0 AND funct='process_mysql_query'");
	MYSQL_QUERY_T(admin, "DELETE FROM debug_filters WHERE filename='MySQL_Session.cpp' AND line=0 AND funct='get_pkts_from_client'");
	// If the filter was present it will be automatically recreated by the tester.
	MYSQL_QUERY_T(admin, "LOAD DEBUG TO RUNTIME");

	// Open the SQLite3 db for debugging
	const string db_path { get_env("REGULAR_INFRA_DATADIR") + "/proxysql_debug.db" };
	sqlite3* sq3_db = nullptr;

	int odb_err = open_sqlite3_db(db_path, &sq3_db, SQLITE_OPEN_READONLY);
	if (odb_err) { return EXIT_FAILURE; }
	char* prg_err { nullptr };

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

	ext_val_t<int> init_mem_stats { mysql_query_ext_val(admin, q_query_rules_mem_stats, -1) };
	CHECK_EXT_VAL(init_mem_stats);
	diag("Initial 'mysql_query_rules_memory' of '%d'", init_mem_stats.val);

	c_err = create_fast_routing_rules_range(cl, admin, rng_init, rng_end);
	if (c_err) { return EXIT_FAILURE; }
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	diag("Warm-up threads to ensure the QueryProcessor maps are build");
	threads_warmup(cl, admin, sq3_db);

	// Check that fast_routing rules are being properly triggered
	const string init_algo_str { init_algo == 1 ? "thread-local" : "global" };
	int chk_res = check_fast_routing_rules(cl, proxy, admin, rng_init, rng_end, init_algo_str, errlog, sq3_db);
	if (chk_res) { return EXIT_FAILURE; }
	printf("\n");

	ext_val_t<int> old_mem_stats { mysql_query_ext_val(admin, q_query_rules_mem_stats, -1) };
	CHECK_EXT_VAL(old_mem_stats);

	diag("*ONLY* Changing the algorithm shouldn't have any effect");
	diag("Testing 'query_rules_fast_routing_algorithm=%d'", new_algo);
	MYSQL_QUERY_T(admin, ("SET mysql-query_rules_fast_routing_algorithm=" + std::to_string(new_algo)).c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	// Check that fast_routing rules are being properly triggered
	chk_res = check_fast_routing_rules(cl, proxy, admin, rng_init, rng_end, init_algo_str, errlog, sq3_db);
	if (chk_res) { return EXIT_FAILURE; }
	printf("\n");

	ext_val_t<int> new_mem_stats { mysql_query_ext_val(admin, q_query_rules_mem_stats, -1) };
	CHECK_EXT_VAL(new_mem_stats);

	diag("Memory SHOULDN'T have changed just because of a variable change");
	ok(
		old_mem_stats.val - init_mem_stats.val == new_mem_stats.val - init_mem_stats.val,
		"Memory stats shouldn't increase just by the variable change - old: %d, new: %d",
		old_mem_stats.val - init_mem_stats.val, new_mem_stats.val - init_mem_stats.val
	);

	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	diag("Warm-up threads to ensure the QueryProcessor maps are build");
	threads_warmup(cl, admin, sq3_db);

	const string new_algo_str { new_algo == 1 ? "thread-local" : "global" };
	diag("Search should now be using the '%s' maps", new_algo_str.c_str());
	chk_res = check_fast_routing_rules(cl, proxy, admin, rng_init, rng_end, new_algo_str, errlog, sq3_db);
	if (chk_res) { return EXIT_FAILURE; }

	new_mem_stats = mysql_query_ext_val(admin, q_query_rules_mem_stats, -1);
	CHECK_EXT_VAL(new_mem_stats);

	bool mem_check_res = false;
	string exp_change { "" };

	const auto old_new_diff { old_mem_stats.val - init_mem_stats.val };
	const auto new_init_diff { new_mem_stats.val - init_mem_stats.val };

	if (init_algo == 1 && new_algo == 2) {
		mem_check_res = old_new_diff > new_init_diff;
		exp_change = "decrease";
	} else if (init_algo == 2 && new_algo == 1) {
		mem_check_res = old_new_diff < new_init_diff;
		exp_change = "increase";
	} else {
		mem_check_res = old_new_diff == new_init_diff;
		exp_change = "not change";
	}

	ok(
		mem_check_res,
		"Memory stats should %s after 'LOAD MYSQL QUERY RULES TO RUNTIME' - old: %d, new: %d",
		exp_change.c_str(), old_new_diff, new_init_diff
	);

	sqlite3_close_v2(sq3_db);

	return EXIT_SUCCESS;
};

int main(int argc, char** argv) {
	// `12` logic checks + 20*3 checks per query rule, per test
	plan((2*3 + 2 + 2 + 20*3) * 2);

	CommandLine cl;

	// Seed the random-number gen
	std::srand(std::time(NULL));

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
