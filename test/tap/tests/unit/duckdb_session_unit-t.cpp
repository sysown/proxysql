#include "duckdb_session.h"
#include "duckdb.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cstring>
#include <memory>
#include <string>

namespace {
DuckDBIntercept classify(const char* s) {
	return duckdb_classify_query(s, std::strlen(s));
}

// Runs a single scalar-count query (e.g. "SELECT COUNT(*) FROM t") and
// returns the integer value of its single cell, or -1 on any failure.
// Used to prove double-execution does NOT happen: the whole point of the
// double-execution test is that this count stays 1 after a single
// duckdb_execute_effective() call, not that the response shape looks
// right.
int scalar_count(duckdb_connection conn, const char* sql) {
	duckdb_result res;
	if (duckdb_query(conn, sql, &res) != DuckDBSuccess) {
		duckdb_destroy_result(&res);
		return -1;
	}
	if (duckdb_row_count(&res) != 1 || duckdb_column_count(&res) != 1) {
		duckdb_destroy_result(&res);
		return -1;
	}
	const int64_t v = duckdb_value_int64(&res, 0, 0);
	duckdb_destroy_result(&res);
	return static_cast<int>(v);
}
} // namespace

int main() {
	plan(55);

	ok(classify("SELECT @@version") == DuckDBIntercept::version,
	   "SELECT @@version is intercepted");
	ok(classify("select @@VERSION") == DuckDBIntercept::version,
	   "intercept matching is case-insensitive");
	ok(classify("  SELECT   @@version  ") == DuckDBIntercept::version,
	   "leading, trailing and inner whitespace are tolerated");
	ok(classify("SELECT version()") == DuckDBIntercept::version,
	   "SELECT version() is intercepted");
	ok(classify("SELECT DATABASE()") == DuckDBIntercept::database,
	   "SELECT DATABASE() is intercepted");
	ok(classify("SELECT DATABASE();  ") == DuckDBIntercept::database,
	   "SELECT DATABASE() accepts a trailing semicolon");
	ok(classify("SELECT VERSION();") == DuckDBIntercept::version,
	   "SELECT VERSION() accepts a trailing semicolon");
	ok(classify("SHOW TABLES") == DuckDBIntercept::show_tables,
	   "SHOW TABLES is intercepted");
	ok(classify("SHOW TABLES;") == DuckDBIntercept::show_tables,
	   "SHOW accepts a trailing semicolon");
	ok(classify("SHOW DATABASES") == DuckDBIntercept::show_databases,
	   "SHOW DATABASES is intercepted");
	ok(classify("SHOW SCHEMAS") == DuckDBIntercept::show_schemas,
	   "SHOW SCHEMAS has a distinct metadata path from SHOW DATABASES");
	ok(classify("SET autocommit=1") == DuckDBIntercept::ok_noop,
	   "SET is accepted as a no-op");
	ok(classify("SET threads=2") == DuckDBIntercept::none,
	   "DuckDB-native SET statements are executed instead of swallowed");
	ok(classify("SET NAMES utf8; SELECT 1") == DuckDBIntercept::none,
	   "SET NAMES followed by another statement is not swallowed as a compatibility no-op");
	ok(classify("SELECT * FROM t") == DuckDBIntercept::none,
	   "an ordinary query is not intercepted");
	ok(classify("") == DuckDBIntercept::none,
	   "an empty query is not intercepted");

	// A prefix must not match: "SELECT @@version_comment" is a real query.
	ok(classify("SELECT @@version_comment") == DuckDBIntercept::none,
	   "a longer variable name is not mistaken for @@version");
	ok(classify("SELECT VERSION(); SELECT 1") == DuckDBIntercept::none,
	   "a multi-statement query is not mistaken for a version intercept");

	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::version));
		ok(r && r->columns == 1 && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "the version intercept builds a one-cell resultset");
	}
	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::database));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] != nullptr &&
		   std::string(r->rows[0]->fields[0]) == "memory",
		   "SELECT DATABASE() defaults to memory");
	}
	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::database,
			                              "/var/lib/proxysql/duckdb/x.db"));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] != nullptr &&
		   std::string(r->rows[0]->fields[0]) == "/var/lib/proxysql/duckdb/x.db",
		   "SELECT DATABASE() reports a file-backed path");
	}
	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::database, ":memory:"));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] != nullptr &&
		   std::string(r->rows[0]->fields[0]) == "memory",
		   "SELECT DATABASE() maps :memory: to memory");
	}

	ok(std::strcmp(duckdb_pgsql_sqlstate(DUCKDB_ERROR_PARSER, ""), "42601") == 0,
	   "DuckDB parser errors map to PostgreSQL syntax_error");
	ok(std::strcmp(duckdb_pgsql_sqlstate(DUCKDB_ERROR_INVALID,
	                                  "Parser Error: syntax error"), "42601") == 0,
	   "prepare-time parser errors retain syntax_error SQLSTATE");
	ok(std::strcmp(duckdb_pgsql_sqlstate(DUCKDB_ERROR_CONSTRAINT, ""), "23000") == 0,
	   "DuckDB constraint errors map to integrity_constraint_violation");
	ok(std::strcmp(duckdb_pgsql_sqlstate(DUCKDB_ERROR_CONVERSION, ""), "22018") == 0,
	   "DuckDB conversion errors map to invalid_character_value_for_cast");
	ok(std::strcmp(duckdb_pgsql_sqlstate(DUCKDB_ERROR_INVALID, "unknown"), "XX000") == 0,
	   "unclassified DuckDB errors use PostgreSQL internal_error fallback");

	ok(duckdb_mysql_errno(DUCKDB_ERROR_PARSER, "") == 1064,
	   "DuckDB parser errors map to MySQL ER_PARSE_ERROR");
	ok(std::strcmp(duckdb_mysql_sqlstate(DUCKDB_ERROR_PARSER, ""), "42000") == 0,
	   "DuckDB parser errors map to MySQL SQLSTATE 42000");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT, "") == 1062,
	   "DuckDB constraint errors map to MySQL ER_DUP_ENTRY");
	ok(std::strcmp(duckdb_mysql_sqlstate(DUCKDB_ERROR_CONSTRAINT, ""), "23000") == 0,
	   "DuckDB constraint errors map to MySQL SQLSTATE 23000");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_OUT_OF_MEMORY, "") == 1037,
	   "DuckDB OOM maps to MySQL ER_OUTOFMEMORY");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_INTERRUPT, "") == 1317,
	   "DuckDB interrupt maps to MySQL ER_QUERY_INTERRUPTED");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_INVALID, "unknown") == 1105,
	   "unclassified DuckDB errors use MySQL ER_UNKNOWN_ERROR, not syntax error");
	ok(std::strcmp(duckdb_mysql_sqlstate(DUCKDB_ERROR_INVALID, "unknown"), "HY000") == 0,
	   "unclassified DuckDB errors use MySQL SQLSTATE HY000");

	DuckDBSessionState pgsql_state;
	ok(duckdb_pgsql_message_action(pgsql_state, 'P') == DuckDBPgsqlAction::send_error,
	   "the first extended-query message emits one ErrorResponse");
	ok(duckdb_pgsql_message_action(pgsql_state, 'B') == DuckDBPgsqlAction::discard,
	   "messages after an extended-query error are discarded until Sync");
	ok(duckdb_pgsql_message_action(pgsql_state, 'S') == DuckDBPgsqlAction::send_ready,
	   "Sync ends extended-query error recovery with ReadyForQuery");
	ok(duckdb_pgsql_message_action(pgsql_state, 'Q') == DuckDBPgsqlAction::process,
	   "simple queries resume after Sync");
	DuckDBSessionState pgsql_flush_state;
	ok(duckdb_pgsql_message_action(pgsql_flush_state, 'H') == DuckDBPgsqlAction::discard,
	   "a normal PostgreSQL Flush is consumed as a protocol message, not parsed as SQL");

	// --- Live-connection behavioural tests -------------------------------

	duckdb_database db = nullptr;
	duckdb_connection conn = nullptr;
	if (duckdb_open(":memory:", &db) != DuckDBSuccess ||
	    duckdb_connect(db, &conn) != DuckDBSuccess) {
		BAIL_OUT("could not open an in-memory duckdb");
	}

	ok(duckdb_pgsql_transaction_status(conn) == 'I',
	   "a new DuckDB connection reports PostgreSQL idle transaction state");
	{
		duckdb_result setup;
		if (duckdb_query(conn, "CREATE TABLE tx_error(v VARCHAR)", &setup) != DuckDBSuccess) {
			BAIL_OUT("could not create transaction-error test table");
		}
		duckdb_destroy_result(&setup);
		if (duckdb_query(conn, "INSERT INTO tx_error VALUES ('not-an-integer')", &setup) != DuckDBSuccess) {
			BAIL_OUT("could not populate transaction-error test table");
		}
		duckdb_destroy_result(&setup);

		const DuckDBExecOutcome begin = duckdb_execute_effective(conn, "BEGIN");
		ok(begin.ok && duckdb_pgsql_transaction_status(conn) == 'T',
		   "BEGIN changes ReadyForQuery state to in-transaction");

		const DuckDBExecOutcome failed = duckdb_execute_effective(
			conn, "SELECT CAST(v AS INTEGER) FROM tx_error");
		ok(!failed.ok && duckdb_pgsql_transaction_status(conn) == 'E',
		   "an invalidating DuckDB error changes ReadyForQuery state to failed");

		const DuckDBExecOutcome rollback = duckdb_execute_effective(conn, "ROLLBACK");
		ok(rollback.ok && duckdb_pgsql_transaction_status(conn) == 'I',
		   "ROLLBACK restores ReadyForQuery state to idle");
	}

	{
		// Regression guard for the C3 double-execution risk: INSERT ...
		// RETURNING over a UUID column classifies as QUERY_RESULT (not
		// CHANGED_ROWS) in DuckDB 1.4.5, and its "id" column is
		// unrenderable, so duckdb_execute_effective() decides (from the
		// PREPARED statement's schema, before executing anything) that
		// this needs the rewrap. Preparing the wrap itself then fails --
		// verified directly: in this DuckDB build, wrapping a bare
		// INSERT in `SELECT COLUMNS(*)::VARCHAR FROM (<stmt>)` is a
		// parser error ("syntax error at or near INTO"), since a bare
		// DML statement is not valid FROM-clause subquery content -- so
		// duckdb_execute_effective() falls back to the ORIGINAL prepared
		// statement, which has not executed yet at that point either.
		// Either way `effective` runs exactly once: assert row count,
		// not response shape, which is what actually proves that.
		duckdb_result setup;
		if (duckdb_query(conn,
		        "CREATE TABLE t(id UUID DEFAULT gen_random_uuid(), n INTEGER)",
		        &setup) != DuckDBSuccess) {
			BAIL_OUT("could not create test table t");
		}
		duckdb_destroy_result(&setup);

		const DuckDBExecOutcome outcome =
			duckdb_execute_effective(conn, "INSERT INTO t(n) VALUES (1) RETURNING id");
		ok(outcome.ok, "INSERT ... RETURNING over an unrenderable column does not error");

		const int rows = scalar_count(conn, "SELECT COUNT(*) FROM t");
		ok(rows == 1,
		   "INSERT ... RETURNING over an unrenderable column inserts "
		   "exactly once (not re-executed by the C3 re-query)");

		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] == nullptr,
		   "the RETURNING id is sent as NULL (degraded output) since the "
		   "wrap could not be prepared for this statement shape");
	}

	{
		// The reviewer's example for the P1 double-execution finding:
		// `SELECT [nextval('s')]` returns a LIST (unrenderable), so it
		// takes the rewrap path -- but nextval() is NOT idempotent. The
		// earlier "execute original, detect unrenderable column, execute
		// wrapped as a SECOND duckdb_query() call" design would advance
		// the sequence TWICE per client statement and return the second
		// (discarded-looking) value while silently burning the first.
		// duckdb_execute_effective() now decides whether to wrap from a
		// *prepared* statement's column types -- which does not execute
		// anything -- so `effective` runs exactly once regardless of
		// which branch (original vs. wrapped) is chosen. The sequence
		// ending up at exactly 1, not 2, is the actual proof of that;
		// checking the rendered value alone would NOT catch a double
		// execution (both executions return a list, just with different
		// contents).
		duckdb_result setup;
		if (duckdb_query(conn, "CREATE SEQUENCE seq_nextval_once", &setup) != DuckDBSuccess) {
			BAIL_OUT("could not create test sequence seq_nextval_once");
		}
		duckdb_destroy_result(&setup);

		const DuckDBExecOutcome outcome =
			duckdb_execute_effective(conn, "SELECT [nextval('seq_nextval_once')] AS v");
		ok(outcome.ok,
		   "SELECT [nextval(...)] over an unrenderable LIST column does not error");

		const int cur = scalar_count(conn, "SELECT currval('seq_nextval_once')");
		ok(cur == 1,
		   "nextval() advances the sequence EXACTLY ONCE per client statement "
		   "-- the P1 regression: a lexical-only safety check would have let "
		   "this same statement run twice");

		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr &&
		   std::string(r->rows[0]->fields[0]) == "[1]",
		   "the rendered value ([1]) matches the single sequence advance "
		   "proved above, not a second, discarded execution's value");
	}

	{
		// A trailing `;` is what almost every CLI client sends. Confirmed
		// by probe: wrapping a statement with a trailing `;` in
		// `SELECT COLUMNS(*)::VARCHAR FROM (<sql>)` is a DuckDB parser
		// error, which -- before the fix -- silently fell back to NULL
		// rendering for the single most common input shape there is.
		const DuckDBExecOutcome outcome =
			duckdb_execute_effective(conn, "SELECT gen_random_uuid() AS u;");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "a trailing ';' does not defeat the unrenderable-column rewrap");
	}

	{
		// A trailing line comment immediately before the (implicit)
		// closing paren, with no newline separating them, would
		// otherwise comment out the wrap's closing `)`. Confirmed by
		// probe.
		const DuckDBExecOutcome outcome =
			duckdb_execute_effective(conn, "SELECT gen_random_uuid() AS u -- trailing comment");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "a trailing line comment does not defeat the unrenderable-column rewrap");
	}

	{
		const DuckDBExecOutcome outcome = duckdb_execute_effective(
			conn, "SELECT gen_random_uuid() AS u; -- trailing comment");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "a semicolon before a trailing line comment is removed for rewrap");
	}

	{
		const DuckDBExecOutcome outcome = duckdb_execute_effective(
			conn, "SELECT gen_random_uuid() AS u; /* trailing comment */");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "a semicolon before a trailing block comment is removed for rewrap");
	}

	{
		// Sanity check that the rewrap still fires (and correctly, over
		// a renderable statement) as a control: an ordinary renderable
		// SELECT with a trailing ';' is unaffected either way.
		const DuckDBExecOutcome outcome =
			duckdb_execute_effective(conn, "SELECT 42 AS answer;");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr &&
		   std::string(r->rows[0]->fields[0]) == "42",
		   "an ordinary renderable query with a trailing ';' is unaffected");
	}

	duckdb_disconnect(&conn);
	duckdb_close(&db);

	return exit_status();
}
