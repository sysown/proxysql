/**
 * @file reg_test_4264-commit_rollback-t.cpp
 * @brief Verifies that 'COMMIT' and 'ROLLBACK' are executed in the correct backend connections when several
 *  connections are hold by a session.
 * @details General test methodology:
 *  0. Create database and tables for performing the tests
 *  1. Configure the required 'mysql_servers' and 'mysql_query_rules'.
 *  2. Extract data 'stats_mysql_connection_pool' (and or 'PROXYSQL INTERNAL SESSION').
 *  3. Perform operations (INSERT,COMMIT,ROLLBACK) in the target servers.
 *  4. Extract data again from 'stats_mysql_connection_pool' (and or 'PROXYSQL INTERNAL SESSION').
 *
 *  Repeat the last three elements for every query cycle to test:
 *   - Simple BEGIN, 'COMMIT|ROLLBACK' - Explicit trxs.
 *   - Autocommit=0, Query, 'COMMIT|ROLLBACK' - Implicit trxs.
 *   - Failing queries - Unknown Transaction Status:
 *
 *  Using the previous query cycles, check increasingly complex scenarios:
 *  - With persistent connections:
 *    + Check with explicit transaction in def/non-def hgs.
 *    + Check with explicit transaction in def/non-def hgs + error.
 *    + Check with implicit transaction in def/non-def hgs.
 *    + Check with implicit transaction in def/non-def hgs + error.
 *    + Check no transaction + error.
 *   - Without persistent connections:
 *    + Previous scenarios but on different backend connections.
 *    + Include a 'SAVEPOINT' in a third connection.
 */

#include <chrono>
#include <iomanip>
#include <iostream>

#include <algorithm>
#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>
#include <utility>

#include <stdio.h>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"
#include "proxysql_utils.h"
#include "json.hpp"

using std::function;
using std::pair;
using std::vector;
using std::string;

using std::to_string;
using nlohmann::json;

const uint32_t DF_HG = 0;
const uint32_t TG_HG_1 = 1047;
const uint32_t TG_HG_2 = 1048;
const string TG_HG_STR { to_string(TG_HG_1) };

CommandLine cl;

/**
 * @details Flow for explicit and persistent trxs:
 *  - BEGIN -> Starts a trx, in default hostgroup.
 *    + Check that ConnUsed incremented in that hostgroup.
 *    + Check that query should have been issued in that hostgroup.
 *  - TG_HG_1 - INSERT INTO -> Should try to reach another hostgroup. Failing to do so due to persist.
 *    + Check that query have been executed in the 'BEGIN' hostgroup.
 *  - COMMIT|ROLLBACK -> Should be executed in original hostgroup.
 *    + Check that query have been executed in the 'BEGIN' hostgroup.
 *    + Check that ConnUsed have decreased after query.
 */
int explicit_trx_persist(MYSQL* admin, MYSQL* proxy, const string& trx_cmd) {
	const vector<uint32_t> tg_hgs { DF_HG };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, "BEGIN");
	diag("Only connection should be in use for any hg");
	check_conn_count(admin, "ConnUsed", 1);
	diag("Only connection should be in use for hg '%d'", DF_HG);
	check_conn_count(admin, "ConnUsed", 1, DF_HG);
	diag("Query should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, df_hg_qs + 1, DF_HG);

	diag("Query intentionally targeting unreachable hostgroup due to 'persist'");
	MYSQL_QUERY_T(proxy, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, df_hg_qs + 2, DF_HG);

	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, df_hg_qs + 3, DF_HG);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);

	return EXIT_SUCCESS;
}

/**
 * @details Same check as 'explicit_trx_persist' but trx is created in random hostgroup.
 *  Ensures that default hostgroup routing works as non-default routing.
 */
int explicit_trx_persist_2(MYSQL* admin, MYSQL* proxy, const string& trx_cmd) {
	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, ("/* hostgroup=" + to_string(TG_HG_1) + "*/ BEGIN").c_str());
	diag("Only connection should be in use for hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	diag("Query should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Query intentionally targeting unreachable hostgroup due to 'persist'");
	MYSQL_QUERY_T(proxy, "DO 1");
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);

	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 3, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	return EXIT_SUCCESS;
}

/**
 * @details Tests that explicit transactions via 'BEGIN' and 'COMMIT' with
 *  'transaction_persistent=1' should disable routing, and all operations
 *  should be done in the same backend connection.
 */
int explicit_trx_persist_c(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_persist(admin, proxy, "COMMIT");
}

int explicit_trx_persist_r(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_persist(admin, proxy, "ROLLBACK");
}

int explicit_trx_persist_2_c(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_persist_2(admin, proxy, "COMMIT");
}

int explicit_trx_persist_2_r(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_persist_2(admin, proxy, "ROLLBACK");
}

int implicit_trx_persist(MYSQL* admin, MYSQL* proxy, const string& trx_cmd) {
	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, "SET autocommit=0");

	diag("No conns should be in use for any hostgroup");
	check_conn_count(admin, "ConnUsed", 0);
	diag("No conns should be in use for hg '%d'", DF_HG);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);

	diag("No queries should have been issued to hg '%d'", DF_HG);
	check_query_count(admin, df_hg_qs, DF_HG);

	MYSQL_QUERY_T(proxy, "INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, df_hg_qs + 1, DF_HG);
	check_conn_count(admin, "ConnUsed", 1, DF_HG);

	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, df_hg_qs + 2, DF_HG);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);

	return EXIT_SUCCESS;
}

int implicit_trx_persist_c(MYSQL* admin, MYSQL* proxy) {
	return implicit_trx_persist(admin, proxy, "COMMIT");
}

int implicit_trx_persist_r(MYSQL* admin, MYSQL* proxy) {
	return implicit_trx_persist(admin, proxy, "ROLLBACK");
}

int explicit_trx_persist_no_def_hg(MYSQL* admin, MYSQL* proxy, const string& trx_cmd) {
	const vector<uint32_t> tg_hgs { TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, ("/* hostgroup=" + to_string(TG_HG_1) + "*/ BEGIN").c_str());
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Query intentionally targeting unreachable hostgroup due to 'persist'");
	MYSQL_QUERY_T(proxy, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);

	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 3, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	return EXIT_SUCCESS;
}

int explicit_trx_persist_no_def_hg_c(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_persist_no_def_hg(admin, proxy, "COMMIT");
}

int explicit_trx_persist_no_def_hg_r(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_persist_no_def_hg(admin, proxy, "ROLLBACK");
}

int implicit_trx_persist_no_def_hg(MYSQL* admin, MYSQL* proxy, const string& trx_cmd) {
	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, "SET autocommit=0");

	diag("No conns should be in use for hg '%d'", DF_HG);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);
	diag("No queries should have been issued to hg '%d'", DF_HG);
	check_query_count(admin, df_hg_qs, DF_HG);

	MYSQL_QUERY_T(proxy, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	return EXIT_SUCCESS;
}

int implicit_trx_persist_no_def_hg_c(MYSQL* admin, MYSQL* proxy) {
	return implicit_trx_persist_no_def_hg(admin, proxy, "COMMIT");
}

int implicit_trx_persist_no_def_hg_r(MYSQL* admin, MYSQL* proxy) {
	return implicit_trx_persist_no_def_hg(admin, proxy, "ROLLBACK");
}

/**
 * @details Flow for explicit and persistent trxs:
 *  - BEGIN -> Starts a trx, in default hostgroup.
 *    + Check that ConnUsed incremented in that hostgroup.
 *    + Check that query should have been issued in that hostgroup.
 *  - TG_HG_1 - INSERT INTO -> Should succeed to execute in hostgroup 'N' (no-persist).
 *    + Check that query have been executed in the 'N' hostgroup.
 *  - COMMIT|ROLLBACK -> Should be executed in original hostgroup.
 *    + Check that query have been executed in the 'BEGIN' hostgroup.
 *    + Check that ConnUsed have decreased after query.
 */
int explicit_trx_no_persist(MYSQL* admin, MYSQL*, const string& trx_cmd) {
	MYSQL* proxy_sbtest = mysql_init(NULL);

	if (!mysql_real_connect(proxy_sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_sbtest));
		return EXIT_FAILURE;
	}

	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);

	// Started transaction in 'DF_HG'
	MYSQL_QUERY_T(proxy_sbtest, "BEGIN");
	check_conn_count(admin, "ConnUsed", 1, DF_HG);
	check_query_count(admin, df_hg_qs + 1, DF_HG);

	// Query redirected to 'TG_HG' imposed by query rule
	MYSQL_QUERY_T(proxy_sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	// Query redirected to 'DF_HG' where trx was started
	MYSQL_QUERY_T(proxy_sbtest, trx_cmd.c_str());
	check_query_count(admin, df_hg_qs + 2, DF_HG);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);

	mysql_close(proxy_sbtest);

	return EXIT_SUCCESS;
};

/**
 * @details Same check as 'explicit_trx_no_persist' but trx is created in random hostgroup.
 *  Ensures that default hostgroup routing works as non-default routing.
 */
int explicit_trx_no_persist_2(MYSQL* admin, MYSQL*, const string& trx_cmd) {
	MYSQL* sbtest = mysql_init(NULL);

	if (!mysql_real_connect(sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(sbtest));
		return EXIT_FAILURE;
	}

	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(sbtest, ("/* hostgroup=" + to_string(TG_HG_1) + "*/ BEGIN").c_str());
	diag("Only connection should be in use for hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	diag("Query should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Query intentionally targeting unreachable hostgroup due to 'persist'");
	MYSQL_QUERY_T(sbtest, "DO 1");
	check_query_count(admin, df_hg_qs + 1, DF_HG);

	MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	mysql_close(sbtest);

	return EXIT_SUCCESS;
}

int explicit_trx_no_persist_c(MYSQL* admin, MYSQL*) {
	return explicit_trx_no_persist(admin, nullptr, "COMMIT");
}

int explicit_trx_no_persist_r(MYSQL* admin, MYSQL*) {
	return explicit_trx_no_persist(admin, nullptr, "ROLLBACK");
}

int explicit_trx_no_persist_2_c(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_no_persist_2(admin, proxy, "COMMIT");
}

int explicit_trx_no_persist_2_r(MYSQL* admin, MYSQL* proxy) {
	return explicit_trx_no_persist_2(admin, proxy, "ROLLBACK");
}

int explicit_trx_no_persist_no_def_hg(MYSQL* admin, MYSQL*, const string& trx_cmd) {
	MYSQL* proxy_sbtest = mysql_init(NULL);

	if (!mysql_real_connect(proxy_sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_sbtest));
		return EXIT_FAILURE;
	}

	const vector<uint32_t> tg_hgs { TG_HG_1, TG_HG_2 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_2_qs = std::stol(pre_pool_state.at(TG_HG_2)[POOL_STATS_IDX::QUERIES]);

	// Started transaction in 'TG_HG_2'
	MYSQL_QUERY_T(proxy_sbtest, ("/* hostgroup=" + to_string(TG_HG_2) + " */ BEGIN").c_str());
	check_conn_count(admin, "ConnUsed", 1, TG_HG_2);
	check_query_count(admin, tg_hg_2_qs + 1, TG_HG_2);

	// Query redirected to 'TG_HG' imposed by query rule
	MYSQL_QUERY_T(proxy_sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	// Query redirected to 'TG_HG_2' where trx was started
	MYSQL_QUERY_T(proxy_sbtest, trx_cmd.c_str());
	check_query_count(admin, tg_hg_2_qs + 2, TG_HG_2);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);

	mysql_close(proxy_sbtest);

	return EXIT_SUCCESS;
};

int explicit_trx_no_persist_no_def_hg_c(MYSQL* admin, MYSQL*) {
	return explicit_trx_no_persist_no_def_hg(admin, nullptr, "COMMIT");
}

int explicit_trx_no_persist_no_def_hg_r(MYSQL* admin, MYSQL*) {
	return explicit_trx_no_persist_no_def_hg(admin, nullptr, "ROLLBACK");
}

/**
 * @details Checks that implicit transactions with no persistence execute the rollback in the correct
 *  hostgroup.
 */
int implicit_trx_no_persist_no_def_hg(MYSQL* admin, MYSQL*, const string& trx_cmd) {
	MYSQL* proxy_sbtest = mysql_init(NULL);

	if (!mysql_real_connect(proxy_sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_sbtest));
		return EXIT_FAILURE;
	}

	const vector<uint32_t> tg_hgs { TG_HG_1, TG_HG_2 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_2_qs = std::stol(pre_pool_state.at(TG_HG_2)[POOL_STATS_IDX::QUERIES]);

	// Started transaction in 'DF_HG'
	MYSQL_QUERY_T(proxy_sbtest, "SET autocommit=0");
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);
	check_query_count(admin, tg_hg_1_qs, TG_HG_1);

	// Query redirected to 'TG_HG_1' imposed by query rule, trx started
	MYSQL_QUERY_T(proxy_sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	// Query redirected to 'TG_HG_2' imposed by query rule, non-persistent conn, another trx started
	MYSQL_QUERY_T(proxy_sbtest, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");

	diag("Dump 'conn_pool' stats after previous queries");
	dump_conn_stats(admin, { TG_HG_1, TG_HG_2 });

	diag("Checking that trx was started for previous query on hg '%d'", TG_HG_2);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	diag("Checking that trx was started for previous query on hg '%d'", TG_HG_2);
	check_query_count(admin, tg_hg_2_qs + 1, TG_HG_2);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_2);

	diag("Checking that we currently have two globally started trx");
	check_conn_count(admin, "ConnUsed", 2);

	// Since ProxySQL cannot issue multiple 'COMMIT|ROLLBACK' as a response to a client one, only one of the
	// oppened trxs will received the closing statement.
	MYSQL_QUERY_T(proxy_sbtest, trx_cmd.c_str());
	check_conn_count(admin, "ConnUsed", 1, TG_HG_2);

	MYSQL_QUERY_T(proxy_sbtest, trx_cmd.c_str());
	check_conn_count(admin, "ConnUsed", 0, TG_HG_2);

	mysql_close(proxy_sbtest);

	return EXIT_SUCCESS;
};

int implicit_trx_no_persist_no_def_hg_c(MYSQL* admin, MYSQL*) {
	return implicit_trx_no_persist_no_def_hg(admin, nullptr, "COMMIT");
}

int implicit_trx_no_persist_no_def_hg_r(MYSQL* admin, MYSQL*) {
	return implicit_trx_no_persist_no_def_hg(admin, nullptr, "ROLLBACK");
}

/**
 * @details Flow for persistent-implicit transaction:
 *  - BEGIN executed in hg 'N':
 *    + Check that ConnUsed incremented in that hostgroup.
 *    + Check that query should have been issued in that hostgroup.
 *  - Query failing to be executed in different hg from BEGIN:
 *    + Should target other hg than 'N' but due to persistent be executed in 'N'.
 *    + Check that conns in use have increased in tg hg.
 *    + Check that queries have increased in tg hg.
 *  - COMMIT|ROLLBACK -> Should be executed in hg from prev query.
 *    + Check that command is executed in hg from previous query.
 *    + Check that conns used have decreased in hg.
 */
int explicit_unknown_trx_persist_no_def_hg(
	MYSQL* admin, MYSQL* proxy, const string& trx_cmd
) {
	diag("Ensure 'autocommit=1' for reused connection");
	MYSQL_QUERY_T(proxy, "SET autocommit=1");

	diag("Initial insert to ensure that 'id=1' is taken in the table");
	MYSQL_QUERY_T(proxy, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");

	diag("Checking that a trx wasn't started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	const vector<uint32_t> tg_hgs { TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, ("/* hostgroup=" + to_string(TG_HG_1) + "*/ BEGIN").c_str());
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Query intentionally targeting unreachable hostgroup due to 'persist'");
	int rc = mysql_query_t(
		proxy, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (id,k,c,p) VALUES (1,1,'foo','bar')"
	);
	int err_code = mysql_errno(proxy);
	ok(rc != 0 && err_code == 1062, "Insert should failed - exp_err: 1062, act_err: %d", err_code);

	diag("Queries should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);

	diag("Checking that trx was started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	diag("Issuing '%s' should end the 'unknown-status' trx due to error", trx_cmd.c_str());
	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 3, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	return EXIT_SUCCESS;
}

int explicit_unknown_trx_persist_no_def_hg_c(MYSQL* admin, MYSQL* proxy) {
	return explicit_unknown_trx_persist_no_def_hg(admin, proxy, "COMMIT");
}

int explicit_unknown_trx_persist_no_def_hg_r(MYSQL* admin, MYSQL* proxy) {
	return explicit_unknown_trx_persist_no_def_hg(admin, proxy, "ROLLBACK");
}

/**
 * @details Flow for persistent-implicit transaction with unknown state:
 *  - SET autocommit=0
 *    + Check that conns didn't increase.
 *    + Check that query haven't been issued, intercepted by ProxySQL.
 *  - Query failing to be executed in non-def hg -> Unknown trx state
 *    + Check that conns in use have increased in tg hg.
 *    + Check that queries have increased in tg hg.
 *  - COMMIT|ROLLBACK -> Should be executed in hg from prev query.
 *    + Check that command is executed in hg from previous query.
 *    + Check that conns used have decreased in hg.
 */
int implicit_unknown_trx_persist_no_def_hg(
	MYSQL* admin, MYSQL* proxy, const string& trx_cmd
) {
	diag("Ensure 'autocommit=1' for reused connection");
	MYSQL_QUERY_T(proxy, "SET autocommit=1");

	diag("Initial insert to ensure that 'id=1' is taken in the table");
	MYSQL_QUERY_T(proxy, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");

	diag("Checking that a trx wasn't started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	const vector<uint32_t> tg_hgs { TG_HG_1 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy, "SET autocommit=0");
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);
	check_query_count(admin, tg_hg_1_qs, TG_HG_1);

	int rc = mysql_query_t(
		proxy, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (id,k,c,p) VALUES (1,1,'foo','bar')"
	);
	int err_code = mysql_errno(proxy);
	ok(rc != 0 && err_code == 1062, "Insert should failed - exp_err: 1062, act_err: %d", err_code);

	diag("Query should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Checking that trx was started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	diag("Issuing '%s' should end the 'unknown-status' trx due to error", trx_cmd.c_str());
	MYSQL_QUERY_T(proxy, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	return EXIT_SUCCESS;
}

int implicit_unknown_trx_persist_no_def_hg_c(MYSQL* admin, MYSQL*) {
	return implicit_unknown_trx_persist_no_def_hg(admin, nullptr, "COMMIT");
}

int implicit_unknown_trx_persist_no_def_hg_r(MYSQL* admin, MYSQL*) {
	return implicit_unknown_trx_persist_no_def_hg(admin, nullptr, "ROLLBACK");
}

/**
 * @details Flow for explicit, and unknown non-persistent trxs:
 *  - BEGIN
 *  - Execute failing query in another hg ('N') due to non-persist ('unknown trx status').
 *  - COMMIT|ROLLBACK
 *    + Should be executed in BEGIN hg.
 *  - COMMIT|ROLLBACK
 *    + Should be executed in trx with 'unknown_transaction_status'.
 */
int explicit_and_unknown_trx_no_persist_no_def_hg(
	MYSQL* admin, MYSQL*, const string& trx_cmd
) {
	MYSQL* proxy_sbtest = mysql_init(NULL);

	if (!mysql_real_connect(proxy_sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy_sbtest));
		return EXIT_FAILURE;
	}

	diag("Initial insert to ensure that 'id=1' is taken in the table");
	MYSQL_QUERY_T(
		proxy_sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')"
	);

	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1, TG_HG_2 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_2_qs = std::stol(pre_pool_state.at(TG_HG_2)[POOL_STATS_IDX::QUERIES]);

	MYSQL_QUERY_T(proxy_sbtest, ("/* hostgroup=" + to_string(TG_HG_1) + "*/ BEGIN").c_str());
	diag("Only connection should be in use for hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	diag("Query should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	int rc = mysql_query_t(
		proxy_sbtest, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (id,k,c,p) VALUES (1,1,'foo','bar')"
	);
	int err_code = mysql_errno(proxy_sbtest);
	ok(rc != 0 && err_code == 1062, "Insert should failed - exp_err: 1062, act_err: %d", err_code);

	diag("Queries should have been issued to hg '%d'", TG_HG_2);
	check_query_count(admin, tg_hg_2_qs + 1, TG_HG_2);

	diag("Checking that conn was flagged as 'unknown_transaction_status' on hg '%d'", TG_HG_2);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_2);

	diag("Issuing '%s' should end the initial explicit transaction first", trx_cmd.c_str());
	MYSQL_QUERY_T(proxy_sbtest, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	diag("Issuing '%s' should end the 'unknown-status' trx due to error", trx_cmd.c_str());
	MYSQL_QUERY_T(proxy_sbtest, trx_cmd.c_str());
	check_query_count(admin, tg_hg_2_qs + 2, TG_HG_2);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_2);

	mysql_close(proxy_sbtest);

	return EXIT_SUCCESS;
}

int explicit_and_unknown_trx_no_persist_no_def_hg_c(MYSQL* admin, MYSQL*) {
	return explicit_and_unknown_trx_no_persist_no_def_hg(admin, nullptr, "COMMIT");
}

int explicit_and_unknown_trx_no_persist_no_def_hg_r(MYSQL* admin, MYSQL*) {
	return explicit_and_unknown_trx_no_persist_no_def_hg(admin, nullptr, "ROLLBACK");
}

/**
 * @details Flow for implicit, and unknown non-persistent trxs:
 *  - SET autcommit=0
 *  - Execute query in hg ('N'), this creates a trx.
 *  - Execute failing query in another hg ('M') due to non-persist ('unknown trx status').
 *  - COMMIT|ROLLBACK
 *    + Should be executed in hg 'N'.
 *  - COMMIT|ROLLBACK
 *    + Should be executed in trx with 'unknown_transaction_status', hg 'M'.
 */
int implicit_and_unknown_trx_no_persist_no_def_hg(
	MYSQL* admin, MYSQL*, const string& trx_cmd
) {
	MYSQL* sbtest = mysql_init(NULL);

	if (!mysql_real_connect(sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(sbtest));
		return EXIT_FAILURE;
	}

	diag("Initial insert to ensure that 'id=1' is taken in the table");
	MYSQL_QUERY_T(
		sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')"
	);

	const vector<uint32_t> tg_hgs { TG_HG_1, TG_HG_2 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_2_qs = std::stol(pre_pool_state.at(TG_HG_2)[POOL_STATS_IDX::QUERIES]);

	diag("Checking that a trx wasn't started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	MYSQL_QUERY_T(sbtest, "SET autocommit=0");
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);
	check_query_count(admin, tg_hg_1_qs, TG_HG_1);

	MYSQL_QUERY_T(sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");

	diag("Queries should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Checking that trx was started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	int rc = mysql_query_t(
		sbtest, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (id,k,c,p) VALUES (1,1,'foo','bar')"
	);
	int err_code = mysql_errno(sbtest);
	ok(rc != 0 && err_code == 1062, "Insert should failed - exp_err: 1062, act_err: %d", err_code);

	diag("Queries should have been issued to hg '%d'", TG_HG_2);
	check_query_count(admin, tg_hg_2_qs + 1, TG_HG_2);

	diag("Checking that conn was flagged as 'unknown_transaction_status' on hg '%d'", TG_HG_2);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_2);

	diag("Issuing '%s' should end the initial explicit transaction first", trx_cmd.c_str());
	MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
	check_query_count(admin, tg_hg_1_qs + 2, TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	diag("Issuing '%s' should end the 'unknown-status' trx due to error", trx_cmd.c_str());
	MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
	check_query_count(admin, tg_hg_2_qs + 2, TG_HG_2);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_2);

	mysql_close(sbtest);

	return EXIT_SUCCESS;
}

int implicit_and_unknown_trx_no_persist_no_def_hg_c(MYSQL* admin, MYSQL*) {
	return implicit_and_unknown_trx_no_persist_no_def_hg(admin, nullptr, "COMMIT");
}

int implicit_and_unknown_trx_no_persist_no_def_hg_r(MYSQL* admin, MYSQL*) {
	return implicit_and_unknown_trx_no_persist_no_def_hg(admin, nullptr, "ROLLBACK");
}

/**
 * @details This test involves the three different logics for trx detection. In a non-persistent session:
 *  - Savepoint creation in TG_HG_1
 *    + Check that 'SAVEPOINT' is detected in the conn
 *  - Transaction started for TG_HG_2
 *    + Check that transaction is detected query properly routed
 *  - Error on DF_HG
 *    + Check that error provoques retaining of the conn due to unknown status.
 *  - Three 'COMMIT|ROLLBACK' are issued
 *    + Check that each command is issued in the correct conn
 *
 *  For the final 'COMMIT|ROLLBACK' commands it's expected that:
 *   * First two commands hit either 'SAVEPOINT' or known trx conn.
 *   * Third command hits the conn with 'unknown trx' status.
 */
int implicit_trx_and_savepoints_no_persist_no_def_hg_(
	MYSQL* admin, MYSQL*, const string& trx_cmd
) {
	MYSQL* sbtest = mysql_init(NULL);

	if (!mysql_real_connect(sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(sbtest));
		return EXIT_FAILURE;
	}

	diag("Initial insert to ensure that 'id=1' is taken in the table");
	MYSQL_QUERY_T(
		sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')"
	);

	pool_state_t pre_pool_state {};
	uint32_t df_hg_qs = 0;
	uint32_t tg_hg_1_qs = 0;
	uint32_t tg_hg_2_qs = 0;

	auto op_0 = [&] () -> int {
		const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1, TG_HG_2 };
		const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };

		pre_pool_state = pre_pool_state_res.second;
		df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);
		tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
		tg_hg_2_qs = std::stol(pre_pool_state.at(TG_HG_2)[POOL_STATS_IDX::QUERIES]);

		diag("Checking that a trx wasn't started for previous query on hg '%d'", TG_HG_1);
		check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

		return EXIT_SUCCESS;
	};

	auto op_1 = [&] () -> int {
		// DOC-NOTE: Force refresh 'active_transactions' field in 'INTERNAL SESSION'. Active transactions
		// field is only refreshed if a query is executed in a backend connection which doesn't have the
		// 'SERVER_STATUS_IN_TRANS' flag active. Thus, ProxySQL is forced to look for other "potential active
		// transactions" for the session.
		{
			MYSQL_QUERY_T(sbtest, ("/* hostgroup=" + to_string(TG_HG_1) + " */ SET autocommit=1").c_str());
			MYSQL_QUERY_T(sbtest, ("/* hostgroup=" + to_string(TG_HG_1) + " */ DO 1").c_str());
		}

		json j_session = fetch_internal_session(sbtest);
		int prev_trxs = -1;

		try {
			prev_trxs = j_session["active_transactions"];
		} catch (std::exception& e) {
			diag("ERROR: Accessing 'INTERNAL SESSION' fields failed with error - %s", e.what());
			return EXIT_FAILURE;
		}

		// DOC-NOTE: This autocommit is not forwarded, because in the flow of `op_1, op_2, op_3` no
		// transaction is started, thus, ProxySQL wont forward it, instead, will send it with the next query,
		// which won't count as a `query_sent`. That's the reason for the interval for the the `SAVEPOINT`
		// query to start at `tg_hg_1_qs + 2`. The only autocommit values that are directly forwared, are the
		// ones that can potentially end an ongoing transaction.
		MYSQL_QUERY_T(sbtest, "SET autocommit=0");
		check_conn_count(admin, "ConnUsed", 0, TG_HG_1);
		check_query_count(admin, {tg_hg_1_qs + 1, tg_hg_1_qs + 2}, TG_HG_1);

		MYSQL_QUERY_T(sbtest, ("/* hostgroup=" + to_string(TG_HG_1) + " */ SAVEPOINT s1").c_str());

		diag("Queries should have been issued to hg '%d'", TG_HG_1);
		check_query_count(admin, {tg_hg_1_qs + 2, tg_hg_1_qs + 3}, TG_HG_1);

		diag("Checking that conn is kept ('has_savepoint') due to previous query on hg '%d'", TG_HG_1);
		check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

		j_session = fetch_internal_session(sbtest);
		bool has_savepoint = false;
		int after_trxs = -1;

		try {
			has_savepoint = j_session["backends"][0]["conn"]["status"]["has_savepoint"];
			after_trxs = j_session["active_transactions"];
		} catch (std::exception& e) {
			diag("ERROR: Accessing 'INTERNAL SESSION' fields failed with error - %s", e.what());
			return EXIT_FAILURE;
		}

		bool ok_res = has_savepoint == true && prev_trxs == after_trxs;

		ok(
			ok_res,
			"Savepoint should be present, but no trxs due to MySQL bug #107875 -"
				" savepoint: %d, pre_trxs: %d, after_trxs: %d",
			has_savepoint, prev_trxs, after_trxs
		);
		if (!ok_res) {
			dump_conn_stats(admin, {});
		}

		return EXIT_SUCCESS;
	};

	auto op_2 = [&] () -> int {
		MYSQL_QUERY_T(sbtest, "SET autocommit=0");
		MYSQL_QUERY_T(sbtest, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");

		check_query_count(admin, {tg_hg_2_qs + 1, tg_hg_2_qs + 2}, TG_HG_2);
		check_conn_count(admin, "ConnUsed", 1, TG_HG_2);

		return EXIT_SUCCESS;
	};

	auto op_3 = [&] () -> int {
		MYSQL_QUERY_T(sbtest, "SET autocommit=1");
		int rc = mysql_query_t(sbtest, "INSERT INTO test.commit_rollback (id,k,c,p) VALUES (1,1,'foo','bar')");

		int err_code = mysql_errno(sbtest);
		ok(rc != 0 && err_code == 1062, "Insert should failed - exp_err: 1062, act_err: %d", err_code);

		// DOC-NOTE: This autocommit is potentially forwared to the backend and counted as 'query_sent', this
		// is because, in the cases this is not the first operation, and 'autocommit=0' have been previously
		// executed in the conn, there would be an implicit ongoing transaction when this 'autocommit=1' is
		// received, since this change in autocommit will end the current transaction, ProxySQL is forced to
		// send it to the backend (in contrast to store it for later applying). This is the reason for the
		// query interval of `{df_hg_qs + 1, df_hg_qs + 2}`.
		diag("Checking the two previous queries were issued - AUTOCOMMIT + INSERT");
		check_query_count(admin, {df_hg_qs + 1, df_hg_qs + 2}, DF_HG);
		check_conn_count(admin, "ConnUsed", 1, DF_HG);

		return EXIT_SUCCESS;
	};

	auto op_4 = [&] () -> int {
		MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
		check_conn_count(admin, "ConnUsed", 2);
		check_conn_count(admin, "ConnUsed", 1, DF_HG);

		MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
		check_conn_count(admin, "ConnUsed", 1);
		check_conn_count(admin, "ConnUsed", 1, DF_HG);

		MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
		check_conn_count(admin, "ConnUsed", 0);
		check_conn_count(admin, "ConnUsed", 0, DF_HG);

		return EXIT_SUCCESS;
	};

	vector<pair<function<int()>, string>> ops {
		{ op_1, "OP1 - SavePoint creation in HG '" + to_string(TG_HG_1) + "'" },
		{ op_2, "OP2 - Trx creation with 'autocommit=0' + INSERT in HG '" + to_string(TG_HG_2) + "'" },
		{ op_3, "OP3 - Unknown transaction status with failing 'INSERT' in HG '" + to_string(DF_HG) + "'" },
	};

	vector<vector<uint32_t>> permutations { get_permutations(vector<uint32_t> {1,2,3}) };

	for (const auto& p : permutations) {
		fprintf(stderr, "\n");
		const string p_str {
			std::accumulate(p.begin(), p.end(), std::string(),
				[](const std::string& str, const uint32_t& n) -> std::string {
					return str + (str.length() > 0 ? "," : "") + std::to_string(n);
				}
			)
		};

		diag("Executing test permutation '%s'", p_str.c_str());
		ok(op_0() == EXIT_SUCCESS, "Fetching stats and setup operation succeeded");

		const auto& p_op_1 { ops[p[0] - 1] };
		const auto& p_op_2 { ops[p[1] - 1] };
		const auto& p_op_3 { ops[p[2] - 1] };

		diag("Executing operation - %s", p_op_1.second.c_str());
		ok(p_op_1.first() == EXIT_SUCCESS, "Operation should exit successfully") ;

		diag("Executing operation - %s", p_op_2.second.c_str());
		ok(p_op_2.first() == EXIT_SUCCESS, "Operation should exit successfully") ;

		diag("Executing operation - %s", p_op_3.second.c_str());
		ok(p_op_3.first() == EXIT_SUCCESS, "Operation should exit successfully") ;

		ok(op_4() == EXIT_SUCCESS, "Final '%s' commands executed in correct hgs", trx_cmd.c_str());
	}

	mysql_close(sbtest);

	return EXIT_SUCCESS;
}

/**
 * @details This test involves the three different logics for trx detection. In a non-persistent session:
 *  - Savepoint creation in TG_HG_1
 *    + Check that 'SAVEPOINT' is detected in the conn
 *  - Transaction started for TG_HG_2
 *    + Check that transaction is detected query properly routed
 *  - Error on DF_HG
 *    + Check that error provoques retaining of the conn due to unknown status.
 *  - Three 'COMMIT|ROLLBACK' are issued
 *    + Check that each command is issued in the correct conn
 *
 *  For the final 'COMMIT|ROLLBACK' commands it's expected that:
 *   * First two commands hit either 'SAVEPOINT' or known trx conn.
 *   * Third command hits the conn with 'unknown trx' status.
 */
int implicit_trx_and_savepoints_no_persist_no_def_hg(
	MYSQL* admin, MYSQL*, const string& trx_cmd
) {
	MYSQL* sbtest = mysql_init(NULL);

	if (!mysql_real_connect(sbtest, cl.host, "sbtest1", "sbtest1", NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(sbtest));
		return EXIT_FAILURE;
	}

	diag("Initial insert to ensure that 'id=1' is taken in the table");
	MYSQL_QUERY_T(
		sbtest, "/* TG_HG_1 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')"
	);

	const vector<uint32_t> tg_hgs { DF_HG, TG_HG_1, TG_HG_2 };
	const pair<int,pool_state_t> pre_pool_state_res { fetch_conn_stats(admin, tg_hgs) };
	if (pre_pool_state_res.first) { return EXIT_FAILURE; }

	const pool_state_t& pre_pool_state { pre_pool_state_res.second };
	const uint32_t df_hg_qs = std::stol(pre_pool_state.at(DF_HG)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_1_qs = std::stol(pre_pool_state.at(TG_HG_1)[POOL_STATS_IDX::QUERIES]);
	const uint32_t tg_hg_2_qs = std::stol(pre_pool_state.at(TG_HG_2)[POOL_STATS_IDX::QUERIES]);

	diag("Checking that a trx wasn't started for previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);

	MYSQL_QUERY_T(sbtest, "SET autocommit=0");
	check_conn_count(admin, "ConnUsed", 0, TG_HG_1);
	check_query_count(admin, tg_hg_1_qs, TG_HG_1);

	MYSQL_QUERY_T(sbtest, ("/* hostgroup=" + to_string(TG_HG_1) + " */ SAVEPOINT s1").c_str());

	diag("Queries should have been issued to hg '%d'", TG_HG_1);
	check_query_count(admin, tg_hg_1_qs + 1, TG_HG_1);

	diag("Checking that conn is kept ('has_savepoint') due to previous query on hg '%d'", TG_HG_1);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_1);

	json j_session = fetch_internal_session(sbtest);
	bool has_savepoint = false;
	int trxs = -1;

	try {
		has_savepoint = j_session["backends"][0]["conn"]["status"]["has_savepoint"];
		trxs = j_session["active_transactions"];
	} catch (std::exception& e) {
		diag("Accessing 'INTERNAL SESSION' fields failed with error - %s", e.what());
	}

	ok(
		has_savepoint == true && trxs == 0,
		"Savepoint should be present, but no trxs due to MySQL bug #107875 - savepoint: %d, trxs: %d",
		has_savepoint, trxs
	);

	MYSQL_QUERY_T(sbtest, "/* TG_HG_2 */ INSERT INTO test.commit_rollback (k,c,p) VALUES (1,'foo','bar')");
	check_query_count(admin, tg_hg_2_qs + 1, TG_HG_2);
	check_conn_count(admin, "ConnUsed", 1, TG_HG_2);

	MYSQL_QUERY_T(sbtest, "SET autocommit=1");
	int rc = mysql_query_t(sbtest, "INSERT INTO test.commit_rollback (id,k,c,p) VALUES (1,1,'foo','bar')");
	int err_code = mysql_errno(sbtest);
	ok(rc != 0 && err_code == 1062, "Insert should failed - exp_err: 1062, act_err: %d", err_code);

	diag("Checking the two previous queries were issued - AUTOCOMMIT + INSERT");
	check_query_count(admin, df_hg_qs + 2, DF_HG);
	check_conn_count(admin, "ConnUsed", 1, DF_HG);
	MYSQL_QUERY_T(sbtest, "SET autocommit=0");

	MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
	check_conn_count(admin, "ConnUsed", 2);
	check_conn_count(admin, "ConnUsed", 1, DF_HG);

	MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
	check_conn_count(admin, "ConnUsed", 1);
	check_conn_count(admin, "ConnUsed", 1, DF_HG);

	MYSQL_QUERY_T(sbtest, trx_cmd.c_str());
	check_conn_count(admin, "ConnUsed", 0);
	check_conn_count(admin, "ConnUsed", 0, DF_HG);

	mysql_close(sbtest);

	return EXIT_SUCCESS;
}

int implicit_trx_and_savepoints_no_persist_no_def_hg_c(MYSQL* admin, MYSQL*) {
	return implicit_trx_and_savepoints_no_persist_no_def_hg_(admin, nullptr, "COMMIT");
}

int implicit_trx_and_savepoints_no_persist_no_def_hg_r(MYSQL* admin, MYSQL*) {
	return implicit_trx_and_savepoints_no_persist_no_def_hg(admin, nullptr, "ROLLBACK");
}

struct test_case_t {
	string name;
	function<int(MYSQL*,MYSQL*)> fn;
};

#define create_test_case(name) { #name, name }

const vector<test_case_t> test_cases {
	create_test_case(explicit_trx_persist_c),
	create_test_case(explicit_trx_persist_r),
	create_test_case(explicit_trx_persist_2_c),
	create_test_case(explicit_trx_persist_2_r),
	create_test_case(implicit_trx_persist_c),
	create_test_case(implicit_trx_persist_r),
	create_test_case(explicit_trx_persist_no_def_hg_c),
	create_test_case(explicit_trx_persist_no_def_hg_r),
	create_test_case(implicit_trx_persist_no_def_hg_c),
	create_test_case(implicit_trx_persist_no_def_hg_r),
	create_test_case(explicit_trx_no_persist_c),
	create_test_case(explicit_trx_no_persist_r),
	create_test_case(explicit_trx_no_persist_2_c),
	create_test_case(explicit_trx_no_persist_2_r),
	create_test_case(explicit_trx_no_persist_no_def_hg_c),
	create_test_case(explicit_trx_no_persist_no_def_hg_r),
	create_test_case(implicit_trx_no_persist_no_def_hg_c),
	create_test_case(implicit_trx_no_persist_no_def_hg_r),
	create_test_case(explicit_unknown_trx_persist_no_def_hg_c),
	create_test_case(explicit_unknown_trx_persist_no_def_hg_r),
	create_test_case(explicit_and_unknown_trx_no_persist_no_def_hg_c),
	create_test_case(explicit_and_unknown_trx_no_persist_no_def_hg_r),
	create_test_case(implicit_and_unknown_trx_no_persist_no_def_hg_c),
	create_test_case(implicit_and_unknown_trx_no_persist_no_def_hg_r),
	create_test_case(implicit_trx_and_savepoints_no_persist_no_def_hg_c),
	create_test_case(implicit_trx_and_savepoints_no_persist_no_def_hg_r),
};

int prepare_tables_and_config(MYSQL* admin, MYSQL* proxy) {
	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "DROP TABLE IF EXISTS test.commit_rollback");
	MYSQL_QUERY_T(proxy,
		"CREATE TABLE test.commit_rollback ("
			" id INTEGER NOT NULL AUTO_INCREMENT, "
			" k INTEGER DEFAULT 0 NOT NULL,"
			" c CHAR(120) DEFAULT '' NOT NULL,"
			" p CHAR(60) DEFAULT '' NOT NULL,"
			" PRIMARY KEY (id)"
		")"
	);

	const auto build_server_copy_query = [] (uint32_t tg_hg, uint32_t og_hg) {
		return cstr_format(
			"INSERT INTO mysql_servers (hostgroup_id,hostname,port)"
				" SELECT %d,hostname,port FROM mysql_servers WHERE hostgroup_id=%d",
			tg_hg, og_hg
		).str;
	};

	MYSQL_QUERY_T(admin, ("DELETE FROM mysql_servers WHERE hostgroup_id=" + to_string(TG_HG_1)).c_str());
	MYSQL_QUERY_T(admin, ("DELETE FROM mysql_servers WHERE hostgroup_id=" + to_string(TG_HG_2)).c_str());

	MYSQL_QUERY_T(admin, build_server_copy_query(TG_HG_1, DF_HG).c_str());
	MYSQL_QUERY_T(admin, build_server_copy_query(TG_HG_2, DF_HG).c_str());
	MYSQL_QUERY_T(admin, "LOAD MYSQL SERVERS TO RUNTIME");

	MYSQL_QUERY_T(admin, "SET mysql-auto_increment_delay_multiplex=0");
	MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES TO RUNTIME");

	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES FROM DISK");
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	MYSQL_QUERY_T(
		admin,
		string {
			"INSERT INTO mysql_query_rules (active,match_pattern,destination_hostgroup,apply) VALUES"
				" (1,'/\\* TG_HG_1 \\*/ INSERT INTO .*'," + to_string(TG_HG_1) + ",1)"
		}.c_str()
	);
	MYSQL_QUERY_T(
		admin,
		string {
			"INSERT INTO mysql_query_rules (active,match_pattern,destination_hostgroup,apply) VALUES"
				" (1,'/\\* TG_HG_2 \\*/ INSERT INTO .*'," + to_string(TG_HG_2) + ",1)"
		}.c_str()
	);
	MYSQL_QUERY_T(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	MYSQL_QUERY_T(admin, "UPDATE mysql_users SET transaction_persistent=0 WHERE username='sbtest1'");
	MYSQL_QUERY_T(admin, "LOAD MYSQL USERS TO RUNTIME");

	return EXIT_SUCCESS;
}

int main(int argc, char** argv) {

	plan(313);

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	int prep_res = prepare_tables_and_config(admin, proxy);
	if (prep_res) {
		goto cleanup;
	}

	for (const auto test : test_cases) {
		fprintf(stderr, "\n");
		diag("Starting test '%s'", test.name.c_str());
		test.fn(admin, proxy);
	}

cleanup:

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
