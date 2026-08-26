#ifndef __DUCKDB_RESULT_H
#define __DUCKDB_RESULT_H

#include "duckdb.h"

class SQLite3_result;

// Converts a materialised duckdb_result into the SQLite3_result that
// core's MySQL and PostgreSQL serialisers both consume.
//
// Every value is rendered with duckdb_value_varchar(), which is correct on
// the wire for the types it actually supports: both text protocols
// transmit values as strings and both serialisers label every column as
// text anyway (MYSQL_TYPE_VAR_STRING / TEXTOID). Verified against DuckDB
// 1.4.5's deprecated C API (duckdb/src/main/capi/cast/generic.hpp,
// GetInternalCValue's switch on deprecated_type): BOOLEAN, TINYINT/
// SMALLINT/INTEGER/BIGINT (+ their U* unsigned variants), FLOAT, DOUBLE,
// DATE, TIME, TIMESTAMP, HUGEINT, UHUGEINT, DECIMAL, INTERVAL, VARCHAR and
// BLOB all render as text correctly (empirically confirmed, e.g. DECIMAL(
// 10,2) -> "1.50", INTERVAL 3 DAY -> "3 days").
//
// duckdb_value_varchar() converts anything else -- any column type not
// listed in that switch -- to a NULL field, because DuckDB's deprecated
// value-materialisation API only special-cases those source types and
// falls through to its "unsupported type" default for the rest. This is
// NOT limited to nested/composite types (LIST, STRUCT, MAP, ARRAY, UNION,
// none of which duckdb_value_varchar can render -- confirmed empirically
// and via GetInternalCValue's `default:` branch). It also silently NULLs
// out several scalar types that are easy to assume "just work": UUID,
// ENUM, BIT, TIME_TZ, TIMESTAMP_TZ, BIGNUM, and the TIMESTAMP_S/MS/NS
// variants are all empirically confirmed to render as NULL too, since
// none of them appear in GetInternalCValue's switch either. Callers that
// route queries capable of producing those column types must not assume
// duckdb_value_varchar() renders them.
//
// duckdb_result_has_nested_column() (declared below) detects the
// container/composite subset of that gap -- LIST, STRUCT, MAP, ARRAY,
// UNION, the types DuckDB's own documentation classifies as "nested" --
// so Task 7 can special-case those. It deliberately does NOT cover the
// non-nested scalar gaps above (UUID, ENUM, BIT, TIME_TZ, TIMESTAMP_TZ,
// BIGNUM, TIMESTAMP_S/MS/NS): those are a separate, real limitation this
// task surfaces but does not attempt to fix or detect.
//
// SQL NULL becomes a null field pointer, which SQLite3_row stores with
// size 0 and SQLite3_to_Postgres emits as a -1 length.
//
// Returns nullptr when the result has no columns. In DuckDB 1.4.5 this is
// NOT what DDL/DML statements (CREATE TABLE, INSERT, ...) produce -- every
// one of those returns a 1-column result named "Count" holding the
// affected-row count, not a zero-column result (empirically verified). A
// genuinely zero-column duckdb_result only occurs for a query with no
// actual SQL statement content (e.g. a comment-only query). Callers that
// need to detect "this was DDL/DML, take the affected-rows path" must
// check duckdb_column_count()/duckdb_rows_changed() on the raw
// duckdb_result themselves -- they cannot rely on this function returning
// nullptr for that case.
//
// The caller owns the returned object and must `delete` it.
SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res);

// Detects columns whose type duckdb_value_varchar() cannot render because
// they are DuckDB "nested"/composite types -- LIST, STRUCT, MAP, ARRAY or
// UNION. duckdb_result_to_sqlite3() silently converts such a column's
// values to SQL NULL (see the comment above); callers that need to
// preserve nested-type data must check this first and handle the result
// differently (e.g. render each such column with duckdb's JSON/Vector
// APIs instead of the deprecated value accessors).
//
// Returns false for a null res or a result with zero columns.
bool duckdb_result_has_nested_column(duckdb_result* res);

#endif // __DUCKDB_RESULT_H
