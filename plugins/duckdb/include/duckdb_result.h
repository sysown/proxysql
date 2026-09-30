#ifndef DUCKDB_RESULT_H
#define DUCKDB_RESULT_H

#include "duckdb.h"

#include <string>
#include <vector>

class SQLite3_result;

struct DuckDBColumnType {
	duckdb_type type;
	uint8_t precision { 0 };
	uint8_t scale { 0 };
};

enum class DuckDBResultProtocol { mysql, pgsql };

// Converts a materialised duckdb_result into the SQLite3_result that
// core's MySQL and PostgreSQL serialisers both consume.
//
// Values are read through DuckDB's C chunk/vector API (string_t lengths for
// VARCHAR/BLOB, typed vector data for everything else). This preserves
// embedded NUL bytes that DuckDB 1.4.5's legacy result materialisation loses
// even through duckdb_value_string().
// This is correct on the wire for the column types the compatibility
// allowlist supports: both text protocols transmit values as strings.
// Optional column_types receives the executed result's schema (including
// decimal precision/scale) before chunk access; plugin serializers use it
// for numeric/boolean/binary metadata and retain text metadata for other types.
// BLOB cells use raw bytes for MySQL and hex BYTEA text for PostgreSQL.
// BOOLEAN cells use 0/1 for MySQL and f/t for PostgreSQL.
// Direct conversion supports scalar numeric/boolean values, DATE/TIME/TIME_TZ,
// TIMESTAMP and its S/MS/NS resolutions, INTERVAL, UUID, VARCHAR and BLOB. Timestamp
// resolutions use native DuckDB value formatting, preserving nanoseconds,
// negative epochs and infinities without another query.
//
// Types outside duckdb_type_renders_as_text() still produce null fields on
// this low-level path. Callers must inspect the result schema and wrap or
// reject unsupported types before conversion; such fields cannot be treated
// as proof of SQL NULL. The session executor performs that preflight.
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
                                         std::string* error = nullptr,
                                         std::vector<DuckDBColumnType>* column_types = nullptr,
                                         DuckDBResultProtocol protocol = DuckDBResultProtocol::mysql);

// Appends one length-aware converted row and translates SQLite's status into
// the converter's error contract. This keeps an oversized row from being
// silently omitted when SQLite3_result rejects its int-sized representation.
bool duckdb_append_sqlite3_row(SQLite3_result& out, char** fields,
                               const unsigned long* sizes, std::string& error);

// True when ANY result column is outside the direct conversion allowlist.
// Returns false for a null result or a result with zero columns.
bool duckdb_result_has_unrenderable_column(duckdb_result* res);

// The single-column predicate behind duckdb_result_has_unrenderable_column()
// above -- "is this type on the direct-conversion compatibility allowlist?" --
// exported so duckdb_session.cpp's prepare-time renderability check
// (deciding, from a duckdb_prepared_statement's column types alone,
// BEFORE anything executes, whether the COLUMNS(*)::VARCHAR rewrap is
// needed) can call the exact same allowlist rather than hand-maintaining
// a second copy of it.
bool duckdb_type_renders_as_text(duckdb_type t);

#endif // DUCKDB_RESULT_H
