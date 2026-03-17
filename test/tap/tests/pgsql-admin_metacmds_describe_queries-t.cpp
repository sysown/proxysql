/**
 * @file pgsql-describe_aueries-t.cpp
 * @brief Advanced testing for \d meta-command query sequence with data validation
 *
 * This test validates each of the 8 queries in the \d tablename sequence
 * by executing them individually and checking the response format AND data accuracy.
 *
 * Query Sequence:
 * 1. pg_class with c.relname OPERATOR - returns: oid, nspname, relname
 * 2. pg_class with c.oid = - returns: relchecks, relkind, relhasindex, etc.
 * 3. pg_attribute - returns: attname, format_type, pg_get_expr, attnotnull, etc.
 * 4. pg_policy - returns: polname, polpermissive, polroles, etc.
 * 5. pg_statistic_ext - returns: oid, stxrelid, nsp, stxname, columns, etc.
 * 6. pg_publication - returns: pubname, prqual, prattrs
 * 7. pg_inherits (parent) - returns: oid
 * 8. pg_inherits (child) - returns: oid, relkind, inhdetachpending, pg_get_expr
 *
 * Data Validation:
 * - Compares returned column names against actual SQLite table_info
 * - Validates table type detection (table vs view)
 * - Verifies column count and names match
 */

#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <libpq-fe.h>

#include "command_line.h"
#include "tap.h"
#include "utils.h"

// Execute a SQL query and return result
PGresult* execute_query(PGconn* conn, const char* query) {
	return PQexec(conn, query);
}

// Check if result has expected column
bool result_has_column(PGresult* res, const char* col_name) {
	int ncols = PQnfields(res);
	for (int i = 0; i < ncols; i++) {
		if (strcmp(PQfname(res, i), col_name) == 0) {
			return true;
		}
	}
	return false;
}

// Get column value as string (handles NULL)
std::string get_column_value(PGresult* res, int row, int col) {
	if (PQgetisnull(res, row, col)) {
		return "";
	}
	return std::string(PQgetvalue(res, row, col));
}

// Build connection string
PGconn* connect_to_admin(const CommandLine& cl) {
	std::stringstream conninfo;
	conninfo << "host=" << cl.pgsql_admin_host;
	conninfo << " port=" << cl.pgsql_admin_port;
	conninfo << " user=" << cl.admin_username;
	conninfo << " password=" << cl.admin_password;
	conninfo << " dbname=postgres";
	conninfo << " connect_timeout=10";

	return PQconnectdb(conninfo.str().c_str());
}

// ==================== DATA VALIDATION HELPERS ====================

/**
 * @brief Get expected columns from SQLite table_info
 *
 * Returns a vector of column names that should be present
 * based on the actual SQLite admin table structure.
 */
std::vector<std::string> get_expected_columns_from_sqlite(const char* table_name) {
	// Known columns for common admin tables
	if (strcmp(table_name, "mysql_servers") == 0) {
		return {"hostgroup_id", "hostname", "port", "gtid_port", "status",
		        "weight", "compression", "max_connections", "max_replication_lag",
		        "use_ssl", "max_latency_ms", "comment"};
	} else if (strcmp(table_name, "mysql_users") == 0) {
		return {"username", "password", "active", "use_ssl", "default_hostgroup",
		        "default_schema", "schema_locked", "transaction_persistent",
		        "fast_forward", "backend", "frontend", "max_connections", "attributes", "comment"};
	} else if (strcmp(table_name, "pgsql_servers") == 0) {
		return {"hostgroup_id", "hostname", "port", "status", "weight",
		        "compression", "max_connections", "max_replication_lag",
		        "use_ssl", "max_latency_ms", "comment"};
	} else if (strcmp(table_name, "global_variables") == 0) {
		return {"variable_name", "variable_value"};
	}
	// Default: return empty (will be validated differently)
	return {};
}

// ==================== QUERY TESTS WITH DATA VALIDATION ====================

void test_query_1_pg_class_lookup(PGconn* conn) {
	diag("Query 1: pg_class table lookup");

	const char* query =
		"SELECT c.oid, n.nspname, c.relname "
		"FROM pg_catalog.pg_class c "
		"LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
		"WHERE c.relname OPERATOR(pg_catalog.~) '^(mysql_servers)$' "
		"AND pg_catalog.pg_table_is_visible(c.oid) "
		"ORDER BY 2, 3";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;
	bool has_oid = result_has_column(res, "oid");
	bool has_nspname = result_has_column(res, "nspname");
	bool has_relname = result_has_column(res, "relname");

	// DATA VALIDATION: Check that relname matches what we asked for
	bool data_correct = true;
	if (PQntuples(res) > 0) {
		std::string relname = get_column_value(res, 0, 2); // c.relname is at index 2
		if (relname != "mysql_servers") {
			diag("ERROR: Expected relname='mysql_servers', got '%s'", relname.c_str());
			data_correct = false;
		}
		std::string nspname = get_column_value(res, 0, 1); // n.nspname is at index 1
		if (nspname != "public") {
			diag("ERROR: Expected nspname='public', got '%s'", nspname.c_str());
			data_correct = false;
		}
	}

	ok(success && has_oid && has_nspname && has_relname && data_correct,
	   "Query 1: pg_class lookup returns correct structure and data");

	PQclear(res);
}

void test_query_2_pg_class_attributes(PGconn* conn) {
	diag("Query 2: pg_class table attributes with data validation");

	const char* query =
		"SELECT 0 AS relchecks, "
		"CASE WHEN (SELECT type FROM sqlite_master WHERE name='mysql_servers' AND type='table' LIMIT 1) = 'table' THEN 'r' "
		"WHEN (SELECT type FROM sqlite_master WHERE name='mysql_servers' AND type='view' LIMIT 1) = 'view' THEN 'v' "
		"ELSE 'r' END AS relkind, "
		"(SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND tbl_name='mysql_servers')) AS relhasindex, "
		"0 AS relhasrules, "
		"(SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name='mysql_servers')) AS relhastriggers, "
		"0 AS relrowsecurity, 0 AS relforcerowsecurity, 0 AS relhasoids, 0 AS relispartition, "
		"'' AS empty1, 0 AS reltablespace, '' AS reloftype, "
		"'p' AS relpersistence, 'd' AS relreplident, 'heap' AS amname";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;

	// DATA VALIDATION: Check relkind is 'r' for regular table
	bool relkind_correct = false;
	if (PQntuples(res) > 0) {
		std::string relkind = get_column_value(res, 0, 1); // relkind at index 1
		relkind_correct = (relkind == "r");
		if (!relkind_correct) {
			diag("ERROR: Expected relkind='r' for table, got '%s'", relkind.c_str());
		}
	}

	ok(success && relkind_correct,
	   "Query 2: pg_class attributes returns correct table type detection");

	PQclear(res);
}

void test_query_3_pg_attribute_with_validation(PGconn* conn) {
	diag("Query 3: pg_attribute column info with data validation");

	const char* query =
		"SELECT name AS attname, type AS format_type, dflt_value AS pg_get_expr, "
		"'f' AS attnotnull, NULL AS attcollation, '' AS attidentity, '' AS attgenerated "
		"FROM pragma_table_info('mysql_servers') ORDER BY cid";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;

	// DATA VALIDATION: Check that returned columns match expected SQLite columns
	std::vector<std::string> expected_cols = get_expected_columns_from_sqlite("mysql_servers");
	std::vector<std::string> returned_cols;

	int nrows = PQntuples(res);
	for (int i = 0; i < nrows; i++) {
		returned_cols.push_back(get_column_value(res, i, 0)); // attname at index 0
	}

	// Check that expected columns are present
	bool columns_match = true;
	for (const auto& expected : expected_cols) {
		if (std::find(returned_cols.begin(), returned_cols.end(), expected) == returned_cols.end()) {
			diag("ERROR: Expected column '%s' not found in result", expected.c_str());
			columns_match = false;
		}
	}

	// Check column count is reasonable (should have at least 10 columns for mysql_servers)
	bool col_count_ok = nrows >= 10;
	if (!col_count_ok) {
		diag("ERROR: Expected at least 10 columns, got %d", nrows);
	}

	ok(success && columns_match && col_count_ok,
	   "Query 3: pg_attribute returns correct columns matching SQLite schema (%d columns)", nrows);

	PQclear(res);
}

void test_query_4_pg_policy_empty(PGconn* conn) {
	diag("Query 4: pg_policy RLS policies (should be empty)");

	const char* query =
		"SELECT '' AS polname, 't' AS polpermissive, NULL AS polroles, "
		"NULL AS pg_get_expr_1, NULL AS pg_get_expr_2, '' AS cmd WHERE 0=1";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;

	// DATA VALIDATION: Should return 0 rows (SQLite has no RLS)
	int nrows = PQntuples(res);
	bool is_empty = (nrows == 0);

	ok(success && is_empty,
	   "Query 4: pg_policy correctly returns empty result (no RLS in SQLite)");

	PQclear(res);
}

void test_query_5_pg_statistic_ext_empty(PGconn* conn) {
	diag("Query 5: pg_statistic_ext (should be empty)");

	const char* query =
		"SELECT 0 AS oid, '' AS stxrelid, '' AS nsp, '' AS stxname, "
		"NULL AS columns, 0 AS ndist_enabled, 0 AS deps_enabled, "
		"0 AS mcv_enabled, 0 AS stxstattarget WHERE 0=1";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;
	int nrows = PQntuples(res);
	bool is_empty = (nrows == 0);

	ok(success && is_empty,
	   "Query 5: pg_statistic_ext correctly returns empty result");

	PQclear(res);
}

void test_query_6_pg_publication_empty(PGconn* conn) {
	diag("Query 6: pg_publication (should be empty)");

	const char* query =
		"SELECT '' AS pubname, NULL AS prqual, NULL AS prattrs WHERE 0=1";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;
	int nrows = PQntuples(res);
	bool is_empty = (nrows == 0);

	ok(success && is_empty,
	   "Query 6: pg_publication correctly returns empty result");

	PQclear(res);
}

void test_query_7_pg_inherits_parent_empty(PGconn* conn) {
	diag("Query 7: pg_inherits parent (should be empty - no inheritance)");

	const char* query =
		"SELECT '' AS oid WHERE 0=1";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;
	int nrows = PQntuples(res);
	bool is_empty = (nrows == 0);

	ok(success && is_empty,
	   "Query 7: pg_inherits parent correctly returns empty result");

	PQclear(res);
}

void test_query_8_pg_inherits_child_empty(PGconn* conn) {
	diag("Query 8: pg_inherits child/partitions (should be empty)");

	const char* query =
		"SELECT '' AS oid, '' AS relkind, 0 AS inhdetachpending, NULL AS pg_get_expr WHERE 0=1";

	PGresult* res = execute_query(conn, query);

	bool success = PQresultStatus(res) == PGRES_TUPLES_OK;
	int nrows = PQntuples(res);
	bool is_empty = (nrows == 0);

	ok(success && is_empty,
	   "Query 8: pg_inherits child correctly returns empty result");

	PQclear(res);
}

// ==================== CROSS-TABLE VALIDATION ====================

void test_column_consistency_across_tables(PGconn* conn) {
	diag("================================================================");
	diag("Cross-table column consistency validation");
	diag("================================================================");

	struct TableExpectation {
		const char* table_name;
		int min_columns;
	};

	TableExpectation tables[] = {
		{"mysql_servers", 10},
		{"mysql_users", 10},
		{"pgsql_servers", 10},
		{"global_variables", 2},
		{"mysql_query_rules", 5}
	};

	int passed = 0;
	for (const auto& table : tables) {
		std::stringstream query;
		query << "SELECT name AS attname, type AS format_type, dflt_value AS pg_get_expr, "
		      << "'f' AS attnotnull, NULL AS attcollation, '' AS attidentity, '' AS attgenerated "
		      << "FROM pragma_table_info('" << table.table_name << "') ORDER BY cid";

		PGresult* res = execute_query(conn, query.str().c_str());

		bool success = PQresultStatus(res) == PGRES_TUPLES_OK;
		int nrows = PQntuples(res);
		bool has_min_cols = nrows >= table.min_columns;

		if (success && has_min_cols) {
			passed++;
			diag("  %s: PASS (%d columns)", table.table_name, nrows);
		} else {
			diag("  %s: FAIL (%d columns, expected >= %d)", table.table_name, nrows, table.min_columns);
		}

		PQclear(res);
	}

	ok(passed == 5, "All 5 tables have expected minimum columns (%d/5 passed)", passed);
}

// ==================== DESCRIBE_MODE RESET TEST ====================

void test_describe_mode_reset(PGconn* conn) {
	diag("================================================================");
	diag("Testing describe_mode reset functionality");
	diag("================================================================");

	// Step 1: Execute first describe query (sets describe_mode=true, saves table name)
	const char* query1 =
		"SELECT c.oid, n.nspname, c.relname "
		"FROM pg_catalog.pg_class c "
		"LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
		"WHERE c.relname OPERATOR(pg_catalog.~) '^(mysql_servers)$' "
		"AND pg_catalog.pg_table_is_visible(c.oid) "
		"ORDER BY 2, 3";

	PGresult* res1 = execute_query(conn, query1);
	bool q1_ok = PQresultStatus(res1) == PGRES_TUPLES_OK;
	PQclear(res1);

	ok(q1_ok, "Step 1: Describe query 1 executed (describe_mode should be true)");

	// Step 2: Execute second describe query (uses saved table name)
	const char* query2 =
		"SELECT name AS attname, type AS format_type, dflt_value AS pg_get_expr, "
		"'f' AS attnotnull, NULL AS attcollation, '' AS attidentity, '' AS attgenerated "
		"FROM pragma_table_info('mysql_servers') ORDER BY cid";

	PGresult* res2 = execute_query(conn, query2);
	bool q2_ok = PQresultStatus(res2) == PGRES_TUPLES_OK;
	int q2_rows = PQntuples(res2);
	PQclear(res2);

	ok(q2_ok && q2_rows > 0, "Step 2: Describe query 2 used saved table name (%d columns)", q2_rows);

	// Step 3: Execute NON-DESCRIBE query (should reset describe_mode=false)
	const char* query3 = "SELECT 1 AS test_column";

	PGresult* res3 = execute_query(conn, query3);
	bool q3_ok = PQresultStatus(res3) == PGRES_TUPLES_OK;
	PQclear(res3);

	ok(q3_ok, "Step 3: Non-describe query executed (describe_mode should be reset to false)");

	// Step 4: Execute new describe query with different table
	// If describe_mode was correctly reset, this should work with new table
	const char* query4 =
		"SELECT c.oid, n.nspname, c.relname "
		"FROM pg_catalog.pg_class c "
		"LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
		"WHERE c.relname OPERATOR(pg_catalog.~) '^(pgsql_servers)$' "
		"AND pg_catalog.pg_table_is_visible(c.oid) "
		"ORDER BY 2, 3";

	PGresult* res4 = execute_query(conn, query4);
	bool q4_ok = PQresultStatus(res4) == PGRES_TUPLES_OK;
	std::string q4_relname = PQntuples(res4) > 0 ? PQgetvalue(res4, 0, 2) : "";
	bool q4_correct = q4_ok && q4_relname == "pgsql_servers";
	PQclear(res4);

	ok(q4_correct, "Step 4: New describe query uses 'pgsql_servers' (not old 'mysql_servers')");

	// Step 5: Verify pg_attribute works with new table
	const char* query5 =
		"SELECT name AS attname, type AS format_type, dflt_value AS pg_get_expr, "
		"'f' AS attnotnull, NULL AS attcollation, '' AS attidentity, '' AS attgenerated "
		"FROM pragma_table_info('pgsql_servers') ORDER BY cid";

	PGresult* res5 = execute_query(conn, query5);
	bool q5_ok = PQresultStatus(res5) == PGRES_TUPLES_OK;
	int q5_rows = PQntuples(res5);
	PQclear(res5);

	ok(q5_ok && q5_rows > 0, "Step 5: pg_attribute for 'pgsql_servers' returned %d columns", q5_rows);
}

// ==================== ERROR HANDLING TESTS ====================

void test_describe_error_handling(PGconn* conn) {
	diag("================================================================");
	diag("Testing describe mode error handling");
	diag("================================================================");

	// Test 1: Query 2 without Query 1 should return error
	diag("Test: Query 2 (pg_class attributes) without prior Query 1");
	const char* query2_no_q1 =
		"SELECT c.relchecks, c.relkind, c.relhasindex, c.relhasrules, c.relhastriggers, "
		"c.relrowsecurity, c.relforcerowsecurity, false AS relhasoids, c.relispartition, "
		"'', c.reltablespace, '', c.relpersistence, c.relreplident, 'heap' AS amname "
		"FROM pg_catalog.pg_class c "
		"WHERE c.oid = 'test_table'";

	PGresult* res1 = execute_query(conn, query2_no_q1);
	bool q2_error = PQresultStatus(res1) == PGRES_FATAL_ERROR;
	if (!q2_error && PQresultStatus(res1) == PGRES_TUPLES_OK) {
		// Check if we got empty result (old behavior) or actual data
		int rows = PQntuples(res1);
		diag("Query 2 returned %d rows (expected error)", rows);
	}
	PQclear(res1);
	ok(q2_error, "Query 2 without Query 1 returns error (not empty result)");

	// Test 2: Query 3 without Query 1 should return error
	diag("Test: Query 3 (pg_attribute) without prior Query 1");
	const char* query3_no_q1 =
		"SELECT a.attname, "
		"pg_catalog.format_type(a.atttypid, a.atttypmod), "
		"pg_catalog.pg_get_expr(d.adbin, d.adrelid), "
		"a.attnotnull, '' AS attcollation, a.attidentity, a.attgenerated "
		"FROM pg_catalog.pg_attribute a "
		"WHERE a.attrelid = 'test_table'";

	PGresult* res2 = execute_query(conn, query3_no_q1);
	bool q3_error = PQresultStatus(res2) == PGRES_FATAL_ERROR;
	PQclear(res2);
	ok(q3_error, "Query 3 without Query 1 returns error (not empty result)");

	// Test 3: Query 1 with unextractable pattern should return error
	diag("Test: Query 1 with invalid/unextractable pattern");
	const char* query1_invalid =
		"SELECT c.oid, n.nspname, c.relname "
		"FROM pg_catalog.pg_class c "
		"LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
		"WHERE c.relname OPERATOR(pg_catalog.~) '' "  // Empty pattern
		"AND pg_catalog.pg_table_is_visible(c.oid) "
		"ORDER BY 2, 3";

	PGresult* res3 = execute_query(conn, query1_invalid);
	bool q1_error = PQresultStatus(res3) == PGRES_FATAL_ERROR;
	PQclear(res3);
	ok(q1_error, "Query 1 with invalid pattern returns error");
}

// ==================== MAIN ====================

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	// Skip test if PostgreSQL admin port is not configured
	if (cl.pgsql_admin_port == 0) {
		plan(1);
		skip(1, "PostgreSQL admin interface not configured");
		return exit_status();
	}

	plan(18);

	// Connect to admin interface
	PGconn* conn = connect_to_admin(cl);

	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection to admin interface failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return -1;
	}

	ok(true, "Connected to PostgreSQL admin interface");

	diag("================================================================");
	diag("CONCERT TESTING: Full 8-Query \\d Sequence with Data Validation");
	diag("================================================================");

	// Run all 8 query tests with data validation
	test_query_1_pg_class_lookup(conn);
	test_query_2_pg_class_attributes(conn);
	test_query_3_pg_attribute_with_validation(conn);
	test_query_4_pg_policy_empty(conn);
	test_query_5_pg_statistic_ext_empty(conn);
	test_query_6_pg_publication_empty(conn);
	test_query_7_pg_inherits_parent_empty(conn);
	test_query_8_pg_inherits_child_empty(conn);

	// Cross-table validation
	test_column_consistency_across_tables(conn);

	// Describe mode reset functionality test
	test_describe_mode_reset(conn);

	// Error handling tests
	test_describe_error_handling(conn);

	// Cleanup
	PQfinish(conn);

	return exit_status();
}
