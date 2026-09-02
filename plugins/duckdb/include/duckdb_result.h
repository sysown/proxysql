#ifndef DUCKDB_RESULT_H
#define DUCKDB_RESULT_H

#include "duckdb.h"

#include <string>

class SQLite3_result;

// Converts a materialised duckdb_result into the SQLite3_result that
// core's MySQL and PostgreSQL serialisers both consume.
//
// Values are read through DuckDB's chunk/vector API and rendered from a
// length-aware Value. This preserves embedded NUL bytes that DuckDB 1.4.5's
// legacy result materialisation loses even through duckdb_value_string().
// This is correct on the wire for the column types the compatibility
// allowlist supports: both text protocols
// transmit values as strings and both serialisers label every column as
// text anyway (MYSQL_TYPE_VAR_STRING / TEXTOID). Verified against DuckDB
// 1.4.5's deprecated C API (duckdb/src/include/duckdb/main/capi/cast/
// generic.hpp, GetInternalCValue's switch on deprecated_type) -- this is
// the authoritative source, not a probed sample of types:
//
//   RENDERS AS TEXT (has a case in that switch): BOOLEAN, TINYINT,
//   SMALLINT, INTEGER, BIGINT, UTINYINT, USMALLINT, UINTEGER, UBIGINT,
//   FLOAT, DOUBLE, DATE, TIME, TIMESTAMP, HUGEINT, UHUGEINT, DECIMAL,
//   INTERVAL, VARCHAR, BLOB -- 20 types, empirically confirmed too (e.g.
//   DECIMAL(10,2) -> "1.50", INTERVAL 3 DAY -> "3 days").
//
//   RENDERS AS NULL (falls through to that switch's `default:` branch,
//   which produces a NULL char* regardless of whether the value is
//   actually SQL NULL): every other duckdb_type. That includes the
//   nested/composite types (LIST, STRUCT, MAP, ARRAY, UNION) but is NOT
//   limited to them -- several ordinary scalar types are just as
//   unrenderable: UUID, ENUM, BIT, TIME_TZ, TIMESTAMP_TZ, BIGNUM, and the
//   TIMESTAMP_S/MS/NS variants are all empirically confirmed to render as
//   NULL, since none of them appear in GetInternalCValue's switch either
//   (UUID in particular is easy to assume "just works" -- it doesn't).
//
// Consequently a null field in the converted SQLite3_result is AMBIGUOUS
// on its own: it means either "the value was genuinely SQL NULL" or "the
// column's type is outside the compatibility allowlist". Callers
// must not treat a null field as proof of SQL NULL. Call
// duckdb_result_has_unrenderable_column() (declared below) on the
// duckdb_result BEFORE conversion to tell the two apart -- it answers
// exactly the question a caller of this function needs answered ("is
// every column on the direct-conversion allowlist?"), not merely
// "does this result contain a nested column?".
//
// Returns nullptr when the result has no columns. In DuckDB 1.4.5 this is
// NOT what DDL/DML statements (CREATE TABLE, INSERT, ...) produce -- every
// one of those returns a 1-column result named "Count" holding the
// affected-row count, not a zero-column result (empirically verified). A
// genuinely zero-column duckdb_result only occurs for a query with no
// actual SQL statement content (e.g. a comment-only query, which is
// itself classified DUCKDB_RESULT_TYPE_QUERY_RESULT -- see below -- despite
// having zero columns). Callers that need to detect "this was DDL/DML,
// take the affected-rows path" must not rely on this function returning
// nullptr for that case; see the next paragraph for the actual signal.
//
// DDL/DML dispatch signal for callers (documented here, not implemented,
// since this file owns the conversion contract but not Task 7's dispatch
// logic): call `duckdb_result_return_type(*res)` (duckdb.h, returns
// duckdb_result_type) on the raw duckdb_result BEFORE conversion.
// Empirically confirmed against DuckDB 1.4.5:
//   DUCKDB_RESULT_TYPE_NOTHING (2)       -- CREATE TABLE, SET, and other
//                                            DDL/session statements with
//                                            no meaningful row count.
//   DUCKDB_RESULT_TYPE_CHANGED_ROWS (1)  -- INSERT/UPDATE/DELETE; the
//                                            1-column "Count" result
//                                            carries the affected-row
//                                            count (duckdb_rows_changed()
//                                            or the "Count" column itself).
//   DUCKDB_RESULT_TYPE_QUERY_RESULT (3)  -- SELECT, and also a
//                                            comment-only/blank statement
//                                            (which is the genuinely
//                                            zero-column case above).
// This is a single already-existing DuckDB C API call with no state or
// error handling of its own to wrap, so it is documented here rather than
// given a redundant one-line accessor -- Task 7 is expected to call
// duckdb_result_return_type() directly against the duckdb_result it
// already holds, alongside whatever else it needs to inspect on the same
// raw result (duckdb_rows_changed(), etc.), rather than through an extra
// indirection that would add nothing beyond forwarding the call.
//
// The caller owns the returned object and must `delete` it. When `error` is
// non-null, conversion failures are reported there and nullptr is returned.
SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res,
                                         std::string* error = nullptr);

// Appends one length-aware converted row and translates SQLite's status into
// the converter's error contract. This keeps an oversized row from being
// silently omitted when SQLite3_result rejects its int-sized representation.
bool duckdb_append_sqlite3_row(SQLite3_result& out, char** fields,
                               const unsigned long* sizes, std::string& error);

// Answers "is every column on the direct-conversion allowlist?" -- true
// if ANY column's duckdb_column_type() is one that GetInternalCValue's
// compatibility switch (see the comment above) does not handle, and
// duckdb_result_to_sqlite3() will therefore deliberately convert that
// column's values to a null field regardless of whether they were
// actually SQL NULL.
//
// This covers the nested/composite types (LIST, STRUCT, MAP, ARRAY,
// UNION) but is NOT limited to them: it also flags non-nested scalar
// types the switch doesn't handle either -- UUID, ENUM, BIT, TIME_TZ,
// TIMESTAMP_TZ, BIGNUM, TIMESTAMP_S, TIMESTAMP_MS, TIMESTAMP_NS, as well
// as any other duckdb_type this build defines that isn't in the switch's
// allowlist (see the implementation: it mirrors the switch's positive
// list rather than hand-maintaining a list of "known bad" types, so a
// future DuckDB version's new type is treated as unrenderable by default
// rather than silently slipping through undetected).
//
// Callers that need to preserve data for a flagged column must handle
// that column differently -- e.g. via duckdb's JSON/Vector APIs -- rather
// than assume duckdb_result_to_sqlite3()'s NULL means SQL NULL.
//
// Returns false for a null res or a result with zero columns.
bool duckdb_result_has_unrenderable_column(duckdb_result* res);

// The single-column predicate behind duckdb_result_has_unrenderable_column()
// above -- "is this type on the direct-conversion compatibility allowlist?" --
// exported so duckdb_session.cpp's prepare-time renderability check
// (deciding, from a duckdb_prepared_statement's column types alone,
// BEFORE anything executes, whether the COLUMNS(*)::VARCHAR rewrap is
// needed) can call the exact same allowlist rather than hand-maintaining
// a second copy of it. See the .cpp for the full mirrors-DuckDB's-switch
// rationale.
bool duckdb_type_renders_as_text(duckdb_type t);

#endif // DUCKDB_RESULT_H
