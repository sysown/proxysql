#include "duckdb_result.h"
#include "duckdb.h"
#include "sqlite3db.h"
#include "tap.h"

#include <climits>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <cstring>
#include <memory>
#include <string>

namespace {

// Runs `sql` on a fresh in-memory database and converts the result.
SQLite3_result* run(duckdb_connection conn, const char* sql,
                    DuckDBResultProtocol protocol = DuckDBResultProtocol::mysql) {
	duckdb_result res;
	if (duckdb_query(conn, sql, &res) != DuckDBSuccess) {
		diag("query failed: %s: %s", sql, duckdb_result_error(&res));
		duckdb_destroy_result(&res);
		return nullptr;
	}
	std::string error;
	SQLite3_result* out = duckdb_result_to_sqlite3(&res, &error, nullptr, protocol);
	if (!error.empty()) diag("conversion failed: %s: %s", sql, error.c_str());
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
	plan(95);

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
		std::unique_ptr<SQLite3_result> mysql(run(conn, "SELECT true, false, NULL::BOOLEAN"));
		ok(field_equals(mysql.get(), 0, 0, "1") && field_equals(mysql.get(), 0, 1, "0") &&
		   mysql->rows[0]->fields[2] == nullptr, "MySQL boolean conversion distinguishes true, false and NULL");
		std::unique_ptr<SQLite3_result> pgsql(run(conn, "SELECT true, false, NULL::BOOLEAN", DuckDBResultProtocol::pgsql));
		ok(field_equals(pgsql.get(), 0, 0, "t") && field_equals(pgsql.get(), 0, 1, "f") &&
		   pgsql->rows[0]->fields[2] == nullptr, "PostgreSQL boolean conversion uses native text representations");
	}

	{
		// The §12 "conversion across integer, float, decimal, timestamp,
		// and blob" claim in the design spec had no assertions backing
		// float/decimal/timestamp/blob before this block -- found during
		// Task 11's own self-check for exactly the defect class the
		// review was about (a claim about test coverage that the test
		// didn't actually assert). All four types render through
		// direct conversion (duckdb_type_renders_as_text() allows
		// them), unlike the nested types covered above.
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT CAST(1.5 AS DOUBLE) AS d"));
		ok(field_equals(r.get(), 0, 0, "1.5"), "float/double value renders as text");
	}

	{
		// Fifteen significant digits cannot preserve every binary64 value.
		// Compare parsed text to independent binary values, including signed zero.
		const struct { const char* literal; double value; } cases[] = {
			{ "1.0000000000000002", 0x1.0000000000001p0 },
			{ "-1.0000000000000002", -0x1.0000000000001p0 },
			{ "9007199254740991", 9007199254740991.0 },
			{ "9007199254740992", 9007199254740992.0 },
			{ "1.7976931348623157e308", std::numeric_limits<double>::max() },
			{ "-1.7976931348623157e308", std::numeric_limits<double>::lowest() },
			{ "2.2250738585072014e-308", std::numeric_limits<double>::min() },
			{ "4.9406564584124654e-324", std::numeric_limits<double>::denorm_min() },
			{ "0.0", 0.0 },
			{ "-0.0", -0.0 }
		};
		for (const auto& c : cases) {
			const std::string sql = std::string("SELECT '") + c.literal + "'::DOUBLE";
			std::unique_ptr<SQLite3_result> r(run(conn, sql.c_str()));
			const char* text = r && r->rows_count == 1 ? r->rows[0]->fields[0] : nullptr;
			char* end = nullptr;
			const double value = text ? std::strtod(text, &end) : 0.0;
			ok(text && end != text && *end == '\0' && value == c.value &&
			   std::signbit(value) == std::signbit(c.value),
			   "DOUBLE %s survives text conversion exactly (received %s)",
			   c.literal, text ? text : "NULL");
		}
		std::unique_ptr<SQLite3_result> special(run(conn,
			"SELECT 'NaN'::DOUBLE, 'Infinity'::DOUBLE, '-Infinity'::DOUBLE, NULL::DOUBLE"));
		ok(field_equals(special.get(), 0, 0, "nan") &&
		   field_equals(special.get(), 0, 1, "inf") &&
		   field_equals(special.get(), 0, 2, "-inf") &&
		   special->rows[0]->fields[3] == nullptr,
		   "nonfinite DOUBLE values and SQL NULL retain their representations");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT CAST(1.23 AS DECIMAL(10,2)) AS dec"));
		ok(field_equals(r.get(), 0, 0, "1.23"), "decimal value renders as text");
	}

	{
		std::unique_ptr<SQLite3_result> min_value(run(conn,
			"SELECT '-170141183460469231731687303715884105728'::HUGEINT"));
		ok(field_equals(min_value.get(), 0, 0,
			"-170141183460469231731687303715884105728"),
		   "minimum signed HUGEINT renders without overflow");

		std::unique_ptr<SQLite3_result> max_value(run(conn,
			"SELECT '170141183460469231731687303715884105727'::HUGEINT"));
		ok(field_equals(max_value.get(), 0, 0,
			"170141183460469231731687303715884105727"),
		   "maximum signed HUGEINT renders exactly");

		std::unique_ptr<SQLite3_result> unsigned_max(run(conn,
			"SELECT '340282366920938463463374607431768211455'::UHUGEINT"));
		ok(field_equals(unsigned_max.get(), 0, 0,
			"340282366920938463463374607431768211455"),
		   "UHUGEINT upper bits are preserved");
	}

	{
		std::unique_ptr<SQLite3_result> positive(run(conn,
			"SELECT '123456789012345678901234567890123456.78'::DECIMAL(38,2)"));
		ok(field_equals(positive.get(), 0, 0,
			"123456789012345678901234567890123456.78"),
		   "wide positive DECIMAL preserves all 128-bit digits");

		std::unique_ptr<SQLite3_result> negative(run(conn,
			"SELECT '-123456789012345678901234567890123456.78'::DECIMAL(38,2)"));
		ok(field_equals(negative.get(), 0, 0,
			"-123456789012345678901234567890123456.78"),
		   "wide negative DECIMAL preserves all 128-bit digits");
	}

	{
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT TIMESTAMP '2024-01-01 12:00:00' AS ts"));
		ok(field_equals(r.get(), 0, 0, "2024-01-01 12:00:00"), "timestamp value renders as text");
	}

	{
		const struct { const char* sql; const char* expected; } cases[] = {
			{ "SELECT '2024-01-02 03:04:05'::TIMESTAMP_S", "2024-01-02 03:04:05" },
			{ "SELECT '2024-01-02 03:04:05.123'::TIMESTAMP_MS", "2024-01-02 03:04:05.123" },
			{ "SELECT '2024-01-02 03:04:05.123456789'::TIMESTAMP_NS", "2024-01-02 03:04:05.123456789" },
			{ "SELECT '1969-12-31 23:59:59.999999999'::TIMESTAMP_NS", "1969-12-31 23:59:59.999999999" },
			{ "SELECT 'infinity'::TIMESTAMP_NS", "infinity" },
			{ "SELECT '-infinity'::TIMESTAMP_MS", "-infinity" },
			{ "SELECT 'infinity'::TIMESTAMP_S", "infinity" }
		};
		for (const auto& c : cases) {
			std::unique_ptr<SQLite3_result> r(run(conn, c.sql));
			ok(field_equals(r.get(), 0, 0, c.expected), "direct timestamp conversion preserves %s", c.expected);
		}
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT NULL::TIMESTAMP_NS"));
		ok(r && r->rows_count == 1 && !r->rows[0]->fields[0], "direct nanosecond timestamp NULL stays NULL");
		ok(duckdb_type_renders_as_text(DUCKDB_TYPE_TIMESTAMP_S) &&
		   duckdb_type_renders_as_text(DUCKDB_TYPE_TIMESTAMP_MS) &&
		   duckdb_type_renders_as_text(DUCKDB_TYPE_TIMESTAMP_NS),
		   "timestamp resolutions do not require a query-wide VARCHAR wrapper");
	}

	{
		// Catch lost offset bits, fractional seconds, sign and NULL during
		// direct conversion of DuckDB's packed TIME_TZ vector storage.
		const char* values[] = {
			"12:34:56.123456+05:30", "00:00:00-03:30",
			"23:59:59.999999+00", "12:34:56+05:30:45",
			"12:34:56-05:30:45", "00:00:00+15:59:59", "24:00:00-15:59:59"
		};
		for (const char* expected : values) {
			const std::string sql = std::string("SELECT '") + expected + "'::TIMETZ";
			std::unique_ptr<SQLite3_result> r(run(conn, sql.c_str()));
			ok(field_equals(r.get(), 0, 0, expected), "direct TIMETZ preserves %s", expected);
		}
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT NULL::TIMETZ"));
		ok(r && r->rows_count == 1 && !r->rows[0]->fields[0], "direct TIMETZ NULL stays NULL");
		ok(duckdb_type_renders_as_text(DUCKDB_TYPE_TIME_TZ), "TIMETZ needs no query-wide VARCHAR wrapper");
	}

	{
		for (const char* expected : { "00:00:00", "00:00:00.000000001", "12:34:56.123456789",
		                              "23:59:59.999999999", "24:00:00" }) {
			const std::string sql = std::string("SELECT '") + expected + "'::TIME_NS, NULL::TIME_NS";
			std::unique_ptr<SQLite3_result> r(run(conn, sql.c_str()));
			ok(field_equals(r.get(), 0, 0, expected) && !r->rows[0]->fields[1],
			   "TIME_NS preserves nanoseconds and NULL: %s (received %s)", expected,
			   r && r->rows_count && r->rows[0]->fields[0] ? r->rows[0]->fields[0] : "NULL");
		}
	}
	{
		for (const char* expected : { "0", "1", "00000000", "10101010", "000101001", "11111111111111111" }) {
			const std::string sql = std::string("SELECT '") + expected + "'::BIT, NULL::BIT";
			std::unique_ptr<SQLite3_result> r(run(conn, sql.c_str()));
			ok(field_equals(r.get(), 0, 0, expected) && !r->rows[0]->fields[1],
			   "BIT preserves leading zeroes, padding and NULL: %s", expected);
		}
		const std::string expected(70001, '1');
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT repeat('1', 70001)::BIT"));
		ok(field_equals(r.get(), 0, 0, expected.c_str()), "BIT renders values larger than inline string storage");
	}
	{
		std::unique_ptr<SQLite3_result> r(run(conn,
			"SELECT ''::ENUM('', 'hello'), 'hello'::ENUM('', 'hello'), NULL::ENUM('', 'hello')"));
		ok(field_equals(r.get(), 0, 0, "") && field_equals(r.get(), 0, 1, "hello") && !r->rows[0]->fields[2],
		   "ENUM renders labels and distinguishes empty labels from NULL");
	}
	// Exercise UINT8/UINT16/UINT32 ordinals, including indices above 255/65535.
	for (int count : { 255, 256, 65537 }) {
		const std::string type = "enum_width_" + std::to_string(count);
		const std::string setup_sql = "CREATE TYPE " + type + " AS ENUM (SELECT 'label_' || i::VARCHAR FROM range(" +
			std::to_string(count) + ") r(i) ORDER BY i)";
		duckdb_result setup;
		if (duckdb_query(conn, setup_sql.c_str(), &setup) != DuckDBSuccess) BAIL_OUT("could not create wide ENUM");
		duckdb_destroy_result(&setup);
		const std::string expected = "label_" + std::to_string(count - 1);
		const std::string sql = "SELECT '" + expected + "'::" + type;
		std::unique_ptr<SQLite3_result> r(run(conn, sql.c_str()));
		ok(field_equals(r.get(), 0, 0, expected.c_str()), "ENUM dictionary of %d labels preserves its final ordinal", count);
	}
	{
		duckdb_result setup;
		if (duckdb_query(conn, "CREATE TYPE enum_nul AS ENUM (SELECT 'a' || chr(0) || 'b')", &setup) != DuckDBSuccess)
			BAIL_OUT("could not create embedded-NUL ENUM");
		duckdb_destroy_result(&setup);
		std::unique_ptr<SQLite3_result> r(run(conn, "SELECT ('a' || chr(0) || 'b')::enum_nul"));
		ok(r && r->rows_count == 1 && r->rows[0]->fields[0] && r->rows[0]->sizes[0] == 3 &&
		   std::memcmp(r->rows[0]->fields[0], "a\0b", 3) == 0, "ENUM labels preserve embedded NUL bytes");
	}
	ok(duckdb_type_renders_as_text(DUCKDB_TYPE_TIME_NS) && duckdb_type_renders_as_text(DUCKDB_TYPE_ENUM) &&
	   duckdb_type_renders_as_text(DUCKDB_TYPE_BIT), "TIME_NS, ENUM and BIT need no query-wide VARCHAR wrapper");

	for (const bool seconds : { true, false }) {
		duckdb_prepared_statement statement = nullptr;
		if (duckdb_prepare(conn, seconds ? "SELECT ?::TIMESTAMP_S" : "SELECT ?::TIMESTAMP_MS", &statement) != DuckDBSuccess)
			BAIL_OUT("could not prepare extreme timestamp fixture");
		duckdb_value value = seconds
			? duckdb_create_timestamp_s({ std::numeric_limits<int64_t>::max() - 1 })
			: duckdb_create_timestamp_ms({ std::numeric_limits<int64_t>::max() - 1 });
		const duckdb_state bound = duckdb_bind_value(statement, 1, value);
		duckdb_destroy_value(&value);
		duckdb_result native;
		if (bound != DuckDBSuccess || duckdb_execute_prepared(statement, &native) != DuckDBSuccess)
			BAIL_OUT("could not execute extreme timestamp fixture");
		duckdb_destroy_prepare(&statement);
		bool rejected = false;
		try {
			std::string error;
			std::unique_ptr<SQLite3_result> r(duckdb_result_to_sqlite3(&native, &error));
			rejected = !r && !error.empty();
		} catch (...) {
			// The conversion API must report failure rather than throw past
			// the executor's rollback path.
		}
		ok(rejected, "out-of-range TIMESTAMP_%s formatting reports a conversion error", seconds ? "S" : "MS");
		duckdb_destroy_result(&native);
	}

	{
		std::unique_ptr<SQLite3_result> dates(run(conn,
			"SELECT DATE 'infinity', DATE '-infinity'"));
		ok(field_equals(dates.get(), 0, 0, "infinity"),
		   "positive infinite DATE renders as infinity");
		ok(field_equals(dates.get(), 0, 1, "-infinity"),
		   "negative infinite DATE renders as -infinity");

		std::unique_ptr<SQLite3_result> timestamps(run(conn,
			"SELECT TIMESTAMP 'infinity', TIMESTAMP '-infinity'"));
		ok(field_equals(timestamps.get(), 0, 0, "infinity"),
		   "positive infinite TIMESTAMP renders as infinity");
		ok(field_equals(timestamps.get(), 0, 1, "-infinity"),
		   "negative infinite TIMESTAMP renders as -infinity");
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
		const char* values[] = {
			"00000000-0000-0000-0000-000000000000",
			"ffffffff-ffff-ffff-ffff-ffffffffffff",
			"7fffffff-ffff-ffff-0123-456789abcdef",
			"80000000-0000-0000-fedc-ba9876543210",
			"00112233-4455-6677-8899-aabbccddeeff"
		};
		for (const char* expected : values) {
			const std::string sql = std::string("SELECT '") + expected + "'::UUID, NULL::UUID";
			std::unique_ptr<SQLite3_result> r(run(conn, sql.c_str()));
			ok(r && r->rows_count == 1 && r->rows[0]->fields[0] &&
			   std::strcmp(r->rows[0]->fields[0], expected) == 0 && !r->rows[0]->fields[1],
			   "direct UUID conversion preserves bits and NULL: %s", expected);
		}
		ok(duckdb_type_renders_as_text(DUCKDB_TYPE_UUID), "UUID needs no VARCHAR query wrapper");
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
