#include "duckdb_result.h"
#include "duckdb.h"
#include "sqlite3db.h"
#include "tap.h"

#include <climits>
#include <cstring>
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

bool field_equals(const SQLite3_result* result, size_t row, size_t column,
	              const char* expected) {
	return result != nullptr && row < result->rows.size() &&
		result->rows[row] != nullptr && result->rows[row]->fields != nullptr &&
		column < static_cast<size_t>(result->rows[row]->cnt) &&
		result->rows[row]->fields[column] != nullptr &&
		std::string(result->rows[row]->fields[column]) == expected;
}

} // namespace

int main() {
	plan(31);

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
		ok(field_equals(r.get(), 0, 0, "42"),
		   "integer value renders as text");
	}

	{
		// The §12 "conversion across integer, float, decimal, timestamp,
		// and blob" claim in the design spec had no assertions backing
		// float/decimal/timestamp/blob before this block -- found during
		// Task 11's own self-check for exactly the defect class the
		// review was about (a claim about test coverage that the test
		// didn't actually assert). All four types render through
		// direct conversion (duckdb_type_renders_as_text() allows
		// them), unlike the nested/UUID/etc. types covered above.
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT CAST(1.5 AS DOUBLE) AS d"));
		ok(field_equals(r.get(), 0, 0, "1.5"), "float/double value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT CAST(1.23 AS DECIMAL(10,2)) AS dec"));
		ok(field_equals(r.get(), 0, 0, "1.23"), "decimal value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT TIMESTAMP '2024-01-01 12:00:00' AS ts"));
		ok(field_equals(r.get(), 0, 0, "2024-01-01 12:00:00"), "timestamp value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT 'hello'::BLOB AS b"));
		ok(field_equals(r.get(), 0, 0, "hello"), "blob value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT NULL AS n, 1 AS m"));
		ok(r && r->rows[0]->fields[0] == nullptr, "SQL NULL becomes a null field");
		ok(r && r->rows[0]->sizes[0] == 0, "null field has zero size");
		ok(r && r->rows[0]->fields[1] != nullptr, "the non-null neighbour survives");
	}

	{
		// A VARCHAR may contain an embedded NUL. The wire serializers consume
		// SQLite3_row::sizes, so preserving the explicit byte count here is the
		// boundary contract that prevents the value being truncated by strlen().
		std::unique_ptr<SQLite3_result> r(
			run(conn, "SELECT varchar FROM test_all_types() WHERE bool"));
		ok(r && r->rows_count == 1 && r->rows[0]->sizes[0] == 6,
		   "VARCHAR conversion preserves the byte length across an embedded NUL");
		ok(r && r->rows[0]->fields[0] != nullptr &&
		   std::memcmp(r->rows[0]->fields[0], "goo\0se", 6) == 0,
		   "VARCHAR conversion preserves every byte across an embedded NUL");
	}

	{
		// The direct compatibility allowlist has no case for LIST/STRUCT/MAP/
		// ARRAY/UNION in its internal cast switch and falls through to a
		// NULL default (verified against DuckDB 1.4.5's
		// GetInternalCValue and empirically via a standalone probe).
		// duckdb_result_to_sqlite3() therefore converts the value to SQL
		// NULL rather than crashing or fabricating data; the predicate
		// below is how a caller distinguishes "genuinely NULL" from
		// "unrenderable type that came out as NULL".
		duckdb_result list_res;
		if (duckdb_query(conn, "SELECT [1,2,3] AS l", &list_res) != DuckDBSuccess) {
			BAIL_OUT("could not run LIST query");
		}
		const bool list_unrenderable = duckdb_result_has_unrenderable_column(&list_res);
		std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&list_res));
		ok(r && r->rows_count == 1, "LIST result converts with one row");
		ok(r && r->rows[0]->fields[0] == nullptr,
		   "LIST value converts to a null field on the direct compatibility path");
		ok(list_unrenderable,
		   "predicate flags the LIST column as unrenderable");
		duckdb_destroy_result(&list_res);

		duckdb_result plain_res;
		if (duckdb_query(conn, "SELECT 42", &plain_res) != DuckDBSuccess) {
			BAIL_OUT("could not run plain query");
		}
		ok(duckdb_result_has_unrenderable_column(&plain_res) == false,
		   "predicate does not flag a plain SELECT 42 result");
		duckdb_destroy_result(&plain_res);
	}

	{
		// UUID is a non-nested SCALAR type that is just as unrenderable as
		// the nested types above -- it has no case in GetInternalCValue's
		// switch either, so the direct compatibility path emits a null field for it
		// despite the value not being SQL NULL. This is exactly the case
		// the predicate must catch that a nested-types-only check would
		// miss: a UUID column would otherwise reach a client as a silent,
		// indistinguishable-from-genuine NULL.
		duckdb_result uuid_res;
		if (duckdb_query(conn, "SELECT gen_random_uuid() AS u", &uuid_res) != DuckDBSuccess) {
			BAIL_OUT("could not run UUID query");
		}
		const bool uuid_unrenderable = duckdb_result_has_unrenderable_column(&uuid_res);
		std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&uuid_res));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] == nullptr,
		   "UUID value converts to a null field on the direct compatibility path");
		ok(uuid_unrenderable,
		   "predicate flags the non-nested UUID column as unrenderable");
		duckdb_destroy_result(&uuid_res);
	}

	{
		// STRUCT is named alongside LIST/MAP/ARRAY/UNION in the comment
		// above the LIST block as one of the nested types the direct
		// compatibility path cannot render, but until now nothing in
		// this file actually asserted that -- it appeared only in prose.
		// Mirrors the LIST block's two checks exactly.
		duckdb_result struct_res;
		if (duckdb_query(conn, "SELECT {'a': 1, 'b': 2} AS s", &struct_res) != DuckDBSuccess) {
			BAIL_OUT("could not run STRUCT query");
		}
		const bool struct_unrenderable = duckdb_result_has_unrenderable_column(&struct_res);
		std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&struct_res));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] == nullptr,
		   "STRUCT value converts to a null field on the direct compatibility path");
		ok(struct_unrenderable,
		   "predicate flags the STRUCT column as unrenderable");
		duckdb_destroy_result(&struct_res);
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT 1 WHERE false"));
		ok(r && r->columns == 1 && r->rows_count == 0,
		   "empty resultset keeps its column definitions");
	}

	{
		char byte = 'x';
		char* fields[] = { &byte };
		const unsigned long sizes[] = { static_cast<unsigned long>(INT_MAX) + 1UL };
		SQLite3_result result(1);
		std::string error;
		ok(!duckdb_append_sqlite3_row(result, fields, sizes, error) &&
		   result.rows_count == 0 && error.find("INT_MAX") != std::string::npos,
		   "DuckDB conversion propagates an oversized row instead of silently dropping it");
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
		ok(duckdb_result_has_unrenderable_column(&res) == false,
		   "predicate returns false for a zero-column result");
		delete r;
		duckdb_destroy_result(&res);
	}

	{
		// Corollary of the above, worth locking down rather than just
		// documenting: CREATE TABLE's result is NOT nullptr from
		// duckdb_result_to_sqlite3(). A caller cannot use "converted to
		// nullptr" as its DDL/DML detection signal -- it must inspect
		// duckdb_result_return_type() on the raw duckdb_result directly,
		// before conversion (see the header's doc comment for the full
		// NOTHING/CHANGED_ROWS/QUERY_RESULT breakdown).
		duckdb_result ddl_res;
		duckdb_query(conn, "CREATE TABLE t(a INTEGER)", &ddl_res);
		std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&ddl_res));
		ok(r != nullptr, "CREATE TABLE's 1-column \"Count\" result is NOT nullptr");
		ok(r && r->columns == 1 && r->rows_count == 0,
		   "CREATE TABLE's result has one column and zero rows");
		ok(duckdb_result_return_type(ddl_res) == DUCKDB_RESULT_TYPE_NOTHING,
		   "CREATE TABLE's return_type is DUCKDB_RESULT_TYPE_NOTHING, the real DDL signal");
		duckdb_destroy_result(&ddl_res);
	}

	ok(duckdb_result_to_sqlite3(nullptr) == nullptr,
	   "a null duckdb_result* converts to nullptr");
	ok(duckdb_result_has_unrenderable_column(nullptr) == false,
	   "predicate returns false for a null duckdb_result*");

	duckdb_disconnect(&conn);
	duckdb_close(&db);
	return exit_status();
}
