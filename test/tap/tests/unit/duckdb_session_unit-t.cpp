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

bool safe_to_rewrap(const char* s) {
	return duckdb_is_safe_to_rewrap(s, std::strlen(s));
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
	plan(23);

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
	ok(classify("SHOW TABLES") == DuckDBIntercept::show_tables,
	   "SHOW TABLES is intercepted");
	ok(classify("SHOW DATABASES") == DuckDBIntercept::show_databases,
	   "SHOW DATABASES is intercepted");
	ok(classify("SET autocommit=1") == DuckDBIntercept::ok_noop,
	   "SET is accepted as a no-op");
	ok(classify("SELECT * FROM t") == DuckDBIntercept::none,
	   "an ordinary query is not intercepted");
	ok(classify("") == DuckDBIntercept::none,
	   "an empty query is not intercepted");

	// A prefix must not match: "SELECT @@version_comment" is a real query.
	ok(classify("SELECT @@version_comment") == DuckDBIntercept::none,
	   "a longer variable name is not mistaken for @@version");

	{
		std::unique_ptr<SQLite3_result> r(
			duckdb_build_intercept_result(DuckDBIntercept::version));
		ok(r && r->columns == 1 && r->rows_count == 1 &&
		   r->rows[0]->fields[0] != nullptr,
		   "the version intercept builds a one-cell resultset");
	}

	// --- duckdb_is_safe_to_rewrap: the C3 double-execution safety gate ---
	//
	// A plain read is safe to re-execute; anything with side effects, or
	// with DML hidden inside a CTE, must never be, since
	// duckdb_execute_effective() would otherwise run it a second time.
	ok(safe_to_rewrap("SELECT 1") == true,
	   "a plain SELECT is safe to rewrap");
	ok(safe_to_rewrap("INSERT INTO t(n) VALUES (1) RETURNING id") == false,
	   "INSERT ... RETURNING is not safe to rewrap");
	ok(safe_to_rewrap("UPDATE t SET n=2 RETURNING id") == false,
	   "UPDATE ... RETURNING is not safe to rewrap");
	ok(safe_to_rewrap("DELETE FROM t RETURNING id") == false,
	   "DELETE ... RETURNING is not safe to rewrap");
	ok(safe_to_rewrap(
	       "WITH x AS (INSERT INTO t(n) VALUES (1) RETURNING id) SELECT * FROM x") == false,
	   "DML hidden inside a CTE's WITH clause is not safe to rewrap, "
	   "even though the statement starts with SELECT/WITH");

	// --- Live-connection behavioural tests -------------------------------

	duckdb_database db = nullptr;
	duckdb_connection conn = nullptr;
	if (duckdb_open(":memory:", &db) != DuckDBSuccess ||
	    duckdb_connect(db, &conn) != DuckDBSuccess) {
		BAIL_OUT("could not open an in-memory duckdb");
	}

	{
		// Regression guard for the C3 double-execution risk: INSERT ...
		// RETURNING over a UUID column classifies as QUERY_RESULT (not
		// CHANGED_ROWS) in DuckDB 1.4.5, and its "id" column is
		// unrenderable, so this statement reaches the re-query branch
		// duckdb_is_safe_to_rewrap gates. NOTE, verified directly: in
		// this DuckDB build the wrap itself is a parser error for a bare
		// INSERT ("syntax error at or near INTO"), so the PRE-FIX code's
		// wrap-failure fallback already happened to keep this specific
		// case at one row -- disabling the gate and re-running this exact
		// test still passes for that reason. The gate is still the
		// correct fix (see the long comment on duckdb_is_safe_to_rewrap):
		// it makes correctness independent of that parser limitation
		// rather than relying on it. This test is kept as the intended
		// regression guard -- assert row count, not response shape --
		// should a future DuckDB grammar change ever make the wrap
		// parse.
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
		   "the RETURNING id is sent as NULL (degraded, not re-executed) "
		   "since the statement is not safe to rewrap");
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
