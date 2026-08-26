#ifndef __DUCKDB_SESSION_H
#define __DUCKDB_SESSION_H

#include "duckdb.h"

#include <cstddef>
#include <cstdint>
#include <string>

class SQLite3_result;
class MySQL_Session;
class PgSQL_Session;
// Forward-declared exactly as proxysql_structs.h itself declares it
// (tag `_PtrSize_t`, aliased to `PtrSize_t`) so this is a *compatible*
// redeclaration once a translation unit later includes proxysql.h for
// the complete type, not a distinct/incomplete type of the same name --
// `struct PtrSize_t;` alone would declare an unrelated tag and every use
// of `pkt->` in the .cpp would fail with "incomplete type", since the
// underlying struct is actually named `_PtrSize_t`, not `PtrSize_t`.
struct _PtrSize_t;
typedef struct _PtrSize_t PtrSize_t;

enum class DuckDBIntercept {
	none,             // hand to DuckDB
	version,
	database,
	show_tables,
	show_databases,
	ok_noop           // answer with a bare OK
};

// Recognises the handful of statements drivers send that DuckDB either
// does not understand or answers differently from what a MySQL/PG client
// expects. Matching ignores case and collapses whitespace, and requires a
// full match so "SELECT @@version_comment" is not taken for "@@version".
DuckDBIntercept duckdb_classify_query(const char* sql, size_t len);

// Builds the canned resultset for an intercept. Returns nullptr for
// `none` and `ok_noop` (the caller sends an OK instead). Caller deletes.
SQLite3_result* duckdb_build_intercept_result(DuckDBIntercept kind);

// One DuckDB connection per connection thread. The listener creates the
// connection after accept and destroys it before the thread exits, so
// thread_local storage is exactly session-scoped here.
struct DuckDBSessionState {
	duckdb_connection conn { nullptr };
};
DuckDBSessionState& duckdb_session_state();

void duckdb_send_mysql_error(MySQL_Session* sess, uint16_t code,
                             const char* sqlstate, const char* msg);
void duckdb_send_pgsql_error(PgSQL_Session* sess, const char* sqlstate,
                             const char* msg);

// Exposed for testing (not called from the header's other public API
// directly -- duckdb_execute_effective() below is the actual gate).
// Returns true only when `sql` is lexically a read: it starts with a
// read keyword (SELECT, WITH, TABLE, VALUES, DESCRIBE, SHOW, PRAGMA,
// EXPLAIN) AND contains no whole-word "RETURNING" anywhere in the
// statement (belt and braces -- a CTE can hide DML inside a WITH, e.g.
// `WITH x AS (INSERT ... RETURNING id) SELECT * FROM x`, which would
// otherwise pass the keyword-prefix check alone). Matching ignores case
// and collapses whitespace exactly like duckdb_classify_query.
//
// This exists because the C3 unrenderable-column re-query
// (duckdb_execute_effective) executes `sql` a SECOND time verbatim
// (wrapped in a subquery); re-executing anything that is not provably
// read-only risks running a DML statement twice. In DuckDB 1.4.5 the
// wrap syntax itself happens to reject bare DML (a parser error, caught
// by the wrap-failure fallback) -- but that protection is incidental to
// today's grammar, not structural, so this gate does not rely on it.
// When this returns false, the re-query is skipped entirely and the
// original (possibly NULL-rendering) result is sent instead.
bool duckdb_is_safe_to_rewrap(const char* sql, size_t len);

// Outcome of duckdb_execute_effective(): everything the session handler
// needs to know to respond to the client, with no protocol-specific
// code in it. Exposed so it can be exercised directly against a live
// duckdb_connection in tests, without a socket-bound
// MySQL_Session/PgSQL_Session.
struct DuckDBExecOutcome {
	bool ok { true };                    // false: `error` is set, nothing else is meaningful
	std::string error;
	bool has_resultset { false };        // true: `result` holds the resultset to send
	SQLite3_result* result { nullptr };  // caller-owned when has_resultset; nullptr otherwise
	int affected_rows { 0 };             // meaningful only when ok && !has_resultset
};

// Runs `effective` (already intercept-rewritten DuckDB SQL) on `conn`
// and applies the DDL/DML/QUERY_RESULT dispatch (C2, via
// duckdb_result_return_type()) and the unrenderable-column re-query
// (C3, via duckdb_result_has_unrenderable_column() and
// duckdb_is_safe_to_rewrap()). The re-query is skipped -- and the
// original, possibly NULL-rendering result sent instead -- both when
// `effective` is not lexically a read (see duckdb_is_safe_to_rewrap)
// and when the wrapped re-query itself fails.
DuckDBExecOutcome duckdb_execute_effective(duckdb_connection conn, const std::string& effective);

// Registered as sess->handler_function. `pa` is core's hardcoded global
// (GloSQLite3Server) and is deliberately ignored: the plugin reaches its
// own state through duckdb_context() / duckdb_session_state().
template <typename S>
void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt);

#endif // __DUCKDB_SESSION_H
