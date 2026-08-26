#include "duckdb_result.h"
#include "duckdb.h"
#include "sqlite3db.h"
#include "tap.h"

#include <memory>
#include <string>

namespace {

// Runs `sql` on a fresh in-memory database and converts the result.
SQLite3_result* run(duckdb_connection conn, const char* sql) {
	duckdb_result res;
	if (duckdb_query(conn, sql, &res) != DuckDBSuccess) {
		duckdb_destroy_result(&res);
		return nullptr;
	}
	SQLite3_result* out = duckdb_result_to_sqlite3(&res);
	duckdb_destroy_result(&res);
	return out;
}

} // namespace

int main() {
	plan(19);

	duckdb_database db = nullptr;
	duckdb_connection conn = nullptr;
	if (duckdb_open(":memory:", &db) != DuckDBSuccess ||
	    duckdb_connect(db, &conn) != DuckDBSuccess) {
		BAIL_OUT("could not open an in-memory duckdb");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT 42 AS answer"));
		ok(r != nullptr, "integer select converts");
		ok(r && r->columns == 1, "one column");
		ok(r && r->rows_count == 1, "one row");
		ok(r && std::string(r->column_definition[0]->name) == "answer",
		   "column name is preserved");
		ok(r && std::string(r->rows[0]->fields[0]) == "42",
		   "integer value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT NULL AS n, 1 AS m"));
		ok(r && r->rows[0]->fields[0] == nullptr, "SQL NULL becomes a null field");
		ok(r && r->rows[0]->sizes[0] == 0, "null field has zero size");
		ok(r && r->rows[0]->fields[1] != nullptr, "the non-null neighbour survives");
	}

	{
		// Nested types cannot round-trip through duckdb's deprecated value
		// API: duckdb_value_varchar() has no case for LIST/STRUCT/MAP/
		// ARRAY/UNION in its internal cast switch and falls through to a
		// NULL default (verified against DuckDB 1.4.5's
		// GetInternalCValue and empirically via a standalone probe).
		// duckdb_result_to_sqlite3() therefore converts the value to SQL
		// NULL rather than crashing or fabricating data; the detector
		// below is how a caller distinguishes "genuinely NULL" from
		// "nested type that came out as NULL".
		duckdb_result list_res;
		if (duckdb_query(conn, "SELECT [1,2,3] AS l", &list_res) != DuckDBSuccess) {
			BAIL_OUT("could not run LIST query");
		}
		std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&list_res));
		ok(r && r->rows_count == 1, "LIST result converts with one row");
		ok(r && r->rows[0]->fields[0] == nullptr,
		   "LIST value converts to a null field (duckdb_value_varchar cannot render nested types)");
		ok(duckdb_result_has_nested_column(&list_res) == true,
		   "detector flags the LIST column as nested");
		duckdb_destroy_result(&list_res);

		duckdb_result plain_res;
		if (duckdb_query(conn, "SELECT 42", &plain_res) != DuckDBSuccess) {
			BAIL_OUT("could not run plain query");
		}
		ok(duckdb_result_has_nested_column(&plain_res) == false,
		   "detector does not flag a plain SELECT 42 result");
		duckdb_destroy_result(&plain_res);
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT 1 WHERE false"));
		ok(r && r->columns == 1 && r->rows_count == 0,
		   "empty resultset keeps its column definitions");
	}

	{
		// A statement with no columns must convert to nullptr so the caller
		// takes the affected-rows path instead of sending an empty set.
		//
		// A genuinely zero-column duckdb_result is NOT what CREATE
		// TABLE/INSERT/etc. produce in DuckDB 1.4.5: every DDL/DML
		// statement returns a 1-column result named "Count" holding the
		// affected-row count (empirically verified). The only way to
		// reach duckdb_column_count() == 0 through duckdb_query() is a
		// statement with no actual SQL content, e.g. a comment-only
		// query -- that is what actually exercises this contract.
		duckdb_result res;
		duckdb_query(conn, "-- no-op", &res);
		SQLite3_result* r = duckdb_result_to_sqlite3(&res);
		ok(r == nullptr, "a genuinely zero-column result converts to nullptr");
		ok(duckdb_result_has_nested_column(&res) == false,
		   "detector returns false for a zero-column result");
		delete r;
		duckdb_destroy_result(&res);
	}

	{
		// Corollary of the above, worth locking down rather than just
		// documenting: CREATE TABLE's result is NOT nullptr from
		// duckdb_result_to_sqlite3(). A caller cannot use "converted to
		// nullptr" as its DDL/DML detection signal -- it must inspect
		// duckdb_column_count()/duckdb_rows_changed() on the raw
		// duckdb_result directly, before conversion.
		duckdb_result ddl_res;
		duckdb_query(conn, "CREATE TABLE t(a INTEGER)", &ddl_res);
		std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&ddl_res));
		ok(r != nullptr, "CREATE TABLE's 1-column \"Count\" result is NOT nullptr");
		ok(r && r->columns == 1 && r->rows_count == 0,
		   "CREATE TABLE's result has one column and zero rows");
		duckdb_destroy_result(&ddl_res);
	}

	ok(duckdb_result_to_sqlite3(nullptr) == nullptr,
	   "a null duckdb_result* converts to nullptr");
	ok(duckdb_result_has_nested_column(nullptr) == false,
	   "detector returns false for a null duckdb_result*");

	duckdb_disconnect(&conn);
	duckdb_close(&db);
	return exit_status();
}
