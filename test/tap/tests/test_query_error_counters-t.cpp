/**
 * @file test_query_error_counters-t.cpp
 * @brief Verifies the per-hostgroup Queries_OK, Queries_ERR, and Queries_warnings
 *  columns added to stats_mysql_connection_pool.
 *
 * @details Test methodology:
 *  1. Record baseline values for Queries_OK, Queries_ERR, Queries_warnings from
 *     stats_mysql_connection_pool for the default hostgroup.
 *  2. Send a batch of successful queries through ProxySQL.
 *     Verify Queries_OK increases by the expected count.
 *     Verify Queries_ERR does not change.
 *  3. Send a query that produces server warnings (INSERT IGNORE on a duplicate row).
 *     Verify Queries_warnings increases.
 *  4. Point to a non-existent server, send a query, verify Queries_ERR increases.
 *     Error numbers >= 2000 are client-side errors (CR_*) and must NOT increment
 *     Queries_ERR — only server-side errors (errno < 2000) count.
 */

#include <cstring>
#include <string>
#include <stdio.h>
#include <unistd.h>

#include "mysql.h"
#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::string;
using std::to_string;

struct pool_counters_t {
	long long queries_ok;
	long long queries_err;
	long long queries_warnings;
};

/**
 * @brief Read Queries_OK, Queries_ERR, Queries_warnings from stats_mysql_connection_pool
 *  for a single hostgroup, summing across all servers in that hostgroup.
 * @return 0 on success, -1 on failure.
 */
int fetch_query_counters(MYSQL* admin, int hostgroup, pool_counters_t& out) {
	char query[256];
	snprintf(query, sizeof(query),
		"SELECT SUM(Queries_OK), SUM(Queries_ERR), SUM(Queries_warnings)"
		" FROM stats_mysql_connection_pool WHERE hostgroup=%d",
		hostgroup
	);

	if (mysql_query(admin, query)) {
		diag("fetch_query_counters: query failed: %s", mysql_error(admin));
		return -1;
	}

	MYSQL_RES* res = mysql_store_result(admin);
	if (!res) {
		diag("fetch_query_counters: mysql_store_result failed: %s", mysql_error(admin));
		return -1;
	}

	MYSQL_ROW row = mysql_fetch_row(res);
	if (!row || !row[0]) {
		diag("fetch_query_counters: no row for hostgroup %d", hostgroup);
		mysql_free_result(res);
		return -1;
	}

	out.queries_ok       = row[0] ? atoll(row[0]) : 0;
	out.queries_err      = row[1] ? atoll(row[1]) : 0;
	out.queries_warnings = row[2] ? atoll(row[2]) : 0;
	mysql_free_result(res);
	return 0;
}

int main(int, char**) {
	CommandLine cl;

	plan(8);

	if (cl.getEnv()) {
		diag("Failed to get required environment variables.");
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return EXIT_FAILURE;
	}

	MYSQL* proxy = mysql_init(NULL);
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxy));
		mysql_close(admin);
		return EXIT_FAILURE;
	}

	// Determine the default hostgroup for the test user so we know which row to read.
	int target_hg = 0;
	{
		char q[256];
		snprintf(q, sizeof(q),
			"SELECT default_hostgroup FROM runtime_mysql_users WHERE username='%s' LIMIT 1",
			cl.username
		);
		if (mysql_query(admin, q) == 0) {
			MYSQL_RES* res = mysql_store_result(admin);
			MYSQL_ROW row = mysql_fetch_row(res);
			if (row && row[0]) target_hg = atoi(row[0]);
			mysql_free_result(res);
		}
		diag("Using default hostgroup %d for user '%s'", target_hg, cl.username);
	}

	// -------------------------------------------------------------------------
	// Warm up: issue one query so at least one server entry exists in the pool.
	// -------------------------------------------------------------------------
	mysql_query(proxy, "DO 1");

	// -------------------------------------------------------------------------
	// Step 1: record baseline counters.
	// -------------------------------------------------------------------------
	pool_counters_t baseline {};
	if (fetch_query_counters(admin, target_hg, baseline) != 0) {
		diag("Failed to read baseline counters — aborting.");
		mysql_close(proxy);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	diag("Baseline: Queries_OK=%lld Queries_ERR=%lld Queries_warnings=%lld",
		baseline.queries_ok, baseline.queries_err, baseline.queries_warnings);

	// -------------------------------------------------------------------------
	// Step 2: send N successful queries, verify Queries_OK increments correctly
	// and Queries_ERR stays the same.
	// -------------------------------------------------------------------------
	const int N_OK = 5;
	for (int i = 0; i < N_OK; i++) {
		MYSQL_QUERY_T(proxy, "DO 1");
	}

	pool_counters_t after_ok {};
	if (fetch_query_counters(admin, target_hg, after_ok) != 0) {
		diag("Failed to read counters after OK queries — aborting.");
		mysql_close(proxy);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	diag("After %d OK queries: Queries_OK=%lld Queries_ERR=%lld Queries_warnings=%lld",
		N_OK, after_ok.queries_ok, after_ok.queries_err, after_ok.queries_warnings);

	ok(
		after_ok.queries_ok >= baseline.queries_ok + N_OK,
		"Queries_OK increases by at least %d after %d successful queries"
			" (baseline=%lld, after=%lld)",
		N_OK, N_OK, baseline.queries_ok, after_ok.queries_ok
	);
	ok(
		after_ok.queries_err == baseline.queries_err,
		"Queries_ERR unchanged after successful queries"
			" (baseline=%lld, after=%lld)",
		baseline.queries_err, after_ok.queries_err
	);

	// -------------------------------------------------------------------------
	// Step 3: generate server warnings.
	// We use CREATE TABLE IF NOT EXISTS on an already-existing table: the server
	// executes the statement, raises Note 1050 ("Table already exists"), and
	// returns warning_count=1 with errno=0 (success). ProxySQL should add 1 to
	// Queries_warnings and 1 to Queries_OK.
	// -------------------------------------------------------------------------
	MYSQL_QUERY_T(proxy, "CREATE DATABASE IF NOT EXISTS test");
	MYSQL_QUERY_T(proxy, "CREATE TABLE IF NOT EXISTS test.qec_warn (id INT PRIMARY KEY)");

	pool_counters_t pre_warn {};
	if (fetch_query_counters(admin, target_hg, pre_warn) != 0) {
		diag("Failed to read pre-warning counters — aborting.");
		mysql_close(proxy);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	diag("Pre-warning baseline: Queries_OK=%lld Queries_ERR=%lld Queries_warnings=%lld",
		pre_warn.queries_ok, pre_warn.queries_err, pre_warn.queries_warnings);

	// Issue the same CREATE TABLE IF NOT EXISTS again — table now exists,
	// server responds with errno=0 + warning_count>=1.
	mysql_query(proxy, "CREATE TABLE IF NOT EXISTS test.qec_warn (id INT PRIMARY KEY)");

	pool_counters_t after_warn {};
	if (fetch_query_counters(admin, target_hg, after_warn) != 0) {
		diag("Failed to read post-warning counters — aborting.");
		mysql_close(proxy);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	diag("After warning query: Queries_OK=%lld Queries_ERR=%lld Queries_warnings=%lld",
		after_warn.queries_ok, after_warn.queries_err, after_warn.queries_warnings);

	ok(
		after_warn.queries_ok == pre_warn.queries_ok + 1,
		"Queries_OK increments by 1 for a successful-but-warning query"
			" (pre=%lld, after=%lld)",
		pre_warn.queries_ok, after_warn.queries_ok
	);
	ok(
		after_warn.queries_warnings > pre_warn.queries_warnings,
		"Queries_warnings increases after a query that produces server warnings"
			" (pre=%lld, after=%lld)",
		pre_warn.queries_warnings, after_warn.queries_warnings
	);
	ok(
		after_warn.queries_err == pre_warn.queries_err,
		"Queries_ERR unchanged after warning-only query"
			" (pre=%lld, after=%lld)",
		pre_warn.queries_err, after_warn.queries_err
	);

	// Cleanup warning test table.
	mysql_query(proxy, "DROP TABLE IF EXISTS test.qec_warn");

	// -------------------------------------------------------------------------
	// Step 4: verify Queries_ERR increments on server-side errors (errno < 2000).
	// We provoke a server error against a non-existent table. This produces
	// ER_NO_SUCH_TABLE (errno 1146), which is < 2000, so it must be counted.
	//
	// IMPORTANT: the error query must route to the same hostgroup we measure
	// (target_hg, the user's default/writer hostgroup). A plain SELECT would be
	// caught by read/write-split query rules (^SELECT -> reader hostgroup) and
	// land on a different hostgroup than target_hg, so its Queries_ERR would not
	// show up here. We therefore use an INSERT (a write), which routes to the
	// default hostgroup just like the DO/CREATE statements above.
	// -------------------------------------------------------------------------
	pool_counters_t pre_err {};
	if (fetch_query_counters(admin, target_hg, pre_err) != 0) {
		diag("Failed to read pre-error counters — aborting.");
		mysql_close(proxy);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	diag("Pre-error baseline: Queries_OK=%lld Queries_ERR=%lld Queries_warnings=%lld",
		pre_err.queries_ok, pre_err.queries_err, pre_err.queries_warnings);

	// This query fails on the backend (table does not exist) — errno 1146 < 2000.
	mysql_query(proxy, "INSERT INTO test.qec_nonexistent_table_for_err_counter (id) VALUES (1)");
	int err = mysql_errno(proxy);
	diag("Error query produced errno=%d: %s", err, mysql_error(proxy));

	ok(
		err > 0 && err < 2000,
		"Error query produced a server-side error (errno %d, must be < 2000 to count toward Queries_ERR)",
		err
	);

	pool_counters_t after_err {};
	if (fetch_query_counters(admin, target_hg, after_err) != 0) {
		diag("Failed to read post-error counters — aborting.");
		mysql_close(proxy);
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	diag("After error query: Queries_OK=%lld Queries_ERR=%lld Queries_warnings=%lld",
		after_err.queries_ok, after_err.queries_err, after_err.queries_warnings);

	ok(
		after_err.queries_err == pre_err.queries_err + 1,
		"Queries_ERR increments by 1 after a server-side error (errno %d < 2000)"
			" (pre=%lld, after=%lld)",
		err, pre_err.queries_err, after_err.queries_err
	);
	ok(
		after_err.queries_ok == pre_err.queries_ok,
		"Queries_OK unchanged after a server-side error"
			" (pre=%lld, after=%lld)",
		pre_err.queries_ok, after_err.queries_ok
	);

	mysql_close(proxy);
	mysql_close(admin);

	return exit_status();
}
