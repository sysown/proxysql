#include "duckdb_session.h"
#include "duckdb_config.h"
#include "duckdb_engine.h"
#include "duckdb.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cstring>
#include <memory>
#include <limits>
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
	plan(81);

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
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT,
		"Constraint Error: Duplicate key violates unique constraint") == 1062,
	   "DuckDB unique constraint errors map to MySQL ER_DUP_ENTRY");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT,
		"Constraint Error: NOT NULL constraint failed: t.v") == 1048,
	   "DuckDB NOT NULL errors map to MySQL ER_BAD_NULL_ERROR");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT,
		"Constraint Error: CHECK constraint failed on table t") == 3819,
	   "DuckDB CHECK errors map to MySQL ER_CHECK_CONSTRAINT_VIOLATED");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT,
		"Constraint Error: Violates foreign key constraint because key \"id: 1\" "
		"does not exist in the referenced table") == 1452,
	   "DuckDB missing-parent errors map to MySQL ER_NO_REFERENCED_ROW_2");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT,
		"Constraint Error: Violates foreign key constraint because key \"id: 1\" "
		"is still referenced by a foreign key in a different table") == 1451,
	   "DuckDB referenced-parent errors map to MySQL ER_ROW_IS_REFERENCED_2");
	ok(duckdb_mysql_errno(DUCKDB_ERROR_CONSTRAINT, "Constraint Error: unknown") == 1105,
	   "unclassified DuckDB constraints do not masquerade as duplicate keys");
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
		const DuckDBExecOutcome begin =
			duckdb_execute_effective(conn, "BEGIN; -- client comment");
		ok(begin.ok && duckdb_pgsql_transaction_status(conn) == 'T',
		   "BEGIN followed by a comment reports in-transaction status");

		const DuckDBExecOutcome rollback =
			duckdb_execute_effective(conn, "ROLLBACK; /* client comment */");
		ok(rollback.ok && duckdb_pgsql_transaction_status(conn) == 'I',
		   "ROLLBACK followed by a comment restores idle transaction status");
	}

	{
		// Unsupported RETURNING values must fail before execution. A
		// sequence also detects execution followed by rollback, since its
		// advance cannot be rolled back.
		duckdb_result setup;
		for (const char* sql : {
			"CREATE SEQUENCE rejected_returning_seq",
			"CREATE TABLE t(id INTEGER[] DEFAULT [1, 2], "
			"n INTEGER DEFAULT nextval('rejected_returning_seq'))",
			"INSERT INTO t(n) VALUES (99)"
		}) {
			if (duckdb_query(conn, sql, &setup) != DuckDBSuccess) {
				BAIL_OUT("could not set up unsupported RETURNING test");
			}
			duckdb_destroy_result(&setup);
		}

		for (const char* sql : {
			"INSERT INTO t DEFAULT VALUES RETURNING id",
			"UPDATE t SET n=100 RETURNING id",
			"DELETE FROM t RETURNING id"
		}) {
			const DuckDBExecOutcome outcome = duckdb_execute_effective(conn, sql);
			std::unique_ptr<SQLite3_result> r(outcome.result);
			ok(!outcome.ok && outcome.error_type == DUCKDB_ERROR_NOT_IMPLEMENTED &&
			   outcome.error.find("VARCHAR") != std::string::npos &&
			   !outcome.has_resultset && !r,
			   "unsupported RETURNING produces an actionable error: %s", sql);
			ok(scalar_count(conn, "SELECT COUNT(*) FROM t") == 1 &&
			   scalar_count(conn, "SELECT n FROM t") == 99,
			   "rejected RETURNING leaves the table unchanged: %s", sql);
		}
		ok(scalar_count(conn, "SELECT nextval('rejected_returning_seq')") == 1,
		   "rejected INSERT does not evaluate the sequence default");

		const DuckDBExecOutcome cast = duckdb_execute_effective(
			conn, "INSERT INTO t(n) VALUES (1) RETURNING id::VARCHAR");
		std::unique_ptr<SQLite3_result> r(cast.result);
		ok(cast.ok && cast.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] && std::strcmp(r->rows[0]->fields[0], "[1, 2]") == 0 &&
		   scalar_count(conn, "SELECT COUNT(*) FROM t") == 2,
		   "explicit VARCHAR RETURNING preserves the value and inserts exactly once");

		const DuckDBExecOutcome begin = duckdb_execute_effective(conn, "BEGIN");
		const DuckDBExecOutcome pending = duckdb_execute_effective(conn, "INSERT INTO t(n) VALUES (2)");
		ok(begin.ok && pending.ok, "create pending work in an explicit transaction");
		const DuckDBExecOutcome rejected = duckdb_execute_effective(conn, "DELETE FROM t RETURNING id");
		ok(!rejected.ok && scalar_count(conn, "SELECT COUNT(*) FROM t") == 3,
		   "rejected RETURNING preserves earlier pending work without deleting rows");
		const DuckDBExecOutcome rollback = duckdb_execute_effective(conn, "ROLLBACK");
		ok(rollback.ok && duckdb_pgsql_transaction_status(conn) == 'I' &&
		   scalar_count(conn, "SELECT COUNT(*) FROM t") == 2,
		   "rollback after rejection discards pending work and restores idle state");
	}

	{
		// Imported/parameter-bound timestamps can exceed the native text
		// formatter's range. A RETURNING conversion error must undo the write.
		duckdb_result setup;
		for (const char* sql : { "CREATE TABLE ts_extreme_source(ts TIMESTAMP_S)",
		                        "CREATE TABLE ts_extreme_target(ts TIMESTAMP_S)" }) {
			if (duckdb_query(conn, sql, &setup) != DuckDBSuccess)
				BAIL_OUT("could not create extreme timestamp tables");
			duckdb_destroy_result(&setup);
		}
		duckdb_prepared_statement statement = nullptr;
		if (duckdb_prepare(conn, "INSERT INTO ts_extreme_source VALUES (?)", &statement) != DuckDBSuccess)
			BAIL_OUT("could not prepare extreme timestamp insert");
		duckdb_value value = duckdb_create_timestamp_s({ std::numeric_limits<int64_t>::max() - 1 });
		const duckdb_state bound = duckdb_bind_value(statement, 1, value);
		duckdb_destroy_value(&value);
		if (bound != DuckDBSuccess || duckdb_execute_prepared(statement, &setup) != DuckDBSuccess)
			BAIL_OUT("could not populate extreme timestamp source");
		duckdb_destroy_result(&setup);
		duckdb_destroy_prepare(&statement);

		const DuckDBExecOutcome outcome = duckdb_execute_effective(conn,
			"INSERT INTO ts_extreme_target SELECT ts FROM ts_extreme_source RETURNING ts");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(!outcome.ok && !outcome.has_resultset && !r &&
		   outcome.error_type == DUCKDB_ERROR_OUT_OF_RANGE,
		   "extreme timestamp RETURNING reports a conversion error");
		ok(scalar_count(conn, "SELECT COUNT(*) FROM ts_extreme_target") == 0 &&
		   scalar_count(conn, "SELECT COUNT(*) FROM ts_extreme_source") == 1 &&
		   duckdb_pgsql_transaction_status(conn) == 'I',
		   "timestamp conversion failure rolls back the mutation and leaves the connection usable");
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
			duckdb_execute_effective(conn, "SELECT [1, 2] AS u;");
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
			duckdb_execute_effective(conn, "SELECT [1, 2] AS u -- trailing comment");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "a trailing line comment does not defeat the unrenderable-column rewrap");
	}

	{
		const DuckDBExecOutcome outcome = duckdb_execute_effective(
			conn, "SELECT [1, 2] AS u; -- trailing comment");
		std::unique_ptr<SQLite3_result> r(outcome.result);
		ok(outcome.ok && outcome.has_resultset && r && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "a semicolon before a trailing line comment is removed for rewrap");
	}

	{
		const DuckDBExecOutcome outcome = duckdb_execute_effective(
			conn, "SELECT [1, 2] AS u; /* trailing comment */");
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

	DuckDBConfigStore managed_cfg;
	DuckDBEngine managed_engine;
	std::string managed_err;
	if (!managed_engine.open(managed_cfg, managed_err)) {
		BAIL_OUT("could not open managed DuckDB engine");
	}
	duckdb_connection managed_conn = nullptr;
	if (!managed_engine.connect(&managed_conn, managed_err)) {
		BAIL_OUT("could not connect to managed DuckDB engine");
	}
	bool handled = false;
	ok(duckdb_execute_managed_set("SET TimeZone='UTC'", managed_engine, handled, managed_err) && !handled,
	   "an unmanaged session SET remains on the ordinary client path");
	ok(duckdb_execute_managed_set("SET threads=5", managed_engine, handled, managed_err) && handled,
	   "a direct managed threads SET is routed through engine control");
	ok(duckdb_execute_managed_set("SET threads=4 -- tune analytics", managed_engine, handled, managed_err) && handled,
	   "a managed SET with a trailing SQL comment is still routed through engine control");
	ok(scalar_count(managed_conn, "SELECT current_setting('threads')::INTEGER") == 4,
	   "the commented managed SET is visible on an existing client connection");
	ok(duckdb_execute_managed_set("SET threads=5; SELECT 1", managed_engine, handled, managed_err) && !handled,
	   "an extra statement after SET stays on the ordinary client path");
	ok(scalar_count(managed_conn, "SELECT current_setting('threads')::INTEGER") == 4,
	   "an extra statement after SET does not change engine-global threads");
	ok(duckdb_execute_managed_set("SET GLOBAL memory_limit='256MB';", managed_engine,
	                              handled, managed_err) && handled,
	   "a quoted direct memory SET is routed through engine control");
	DuckDBEffectiveSettings managed_effective;
	ok(managed_engine.effective_settings(managed_effective, managed_err) &&
	   managed_effective.memory_limit == "244.1 MiB",
	   "direct memory SET uses DuckDB canonical effective readback");
	ok(!duckdb_execute_managed_set("SET access_mode='READ_ONLY'", managed_engine,
	                               handled, managed_err) && handled &&
	   managed_err.find("cannot be changed") != std::string::npos,
	   "a direct startup-only access_mode change is rejected clearly");
	managed_engine.disconnect(&managed_conn);
	managed_engine.close();

	return exit_status();
}
