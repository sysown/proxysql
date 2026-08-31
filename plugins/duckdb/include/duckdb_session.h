#ifndef DUCKDB_SESSION_H
#define DUCKDB_SESSION_H

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
	show_schemas,
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

// Maps DuckDB's typed errors to PostgreSQL SQLSTATEs where the categories
// have an unambiguous counterpart. Unknown categories use XX000.
const char* duckdb_pgsql_sqlstate(duckdb_error_type type, const std::string& message);

// PostgreSQL ReadyForQuery transaction-status byte for a DuckDB connection.
char duckdb_pgsql_transaction_status(duckdb_connection conn);

// Outcome of duckdb_execute_effective(): everything the session handler
// needs to know to respond to the client, with no protocol-specific
// code in it. Exposed so it can be exercised directly against a live
// duckdb_connection in tests, without a socket-bound
// MySQL_Session/PgSQL_Session.
struct DuckDBExecOutcome {
	bool ok { true };                    // false: `error` is set, nothing else is meaningful
	std::string error;
	duckdb_error_type error_type { DUCKDB_ERROR_INVALID };
	bool has_resultset { false };        // true: `result` holds the resultset to send
	SQLite3_result* result { nullptr };  // caller-owned when has_resultset; nullptr otherwise
	int affected_rows { 0 };             // meaningful only when ok && !has_resultset
};

// Runs `effective` (already intercept-rewritten DuckDB SQL) on `conn`
// and applies the DDL/DML/QUERY_RESULT dispatch (C2, via
// duckdb_result_return_type()) and the unrenderable-column rewrap (C3).
//
// C3 is decided from a *prepared* statement's column types -- via
// duckdb_prepared_statement_column_type() and
// duckdb_type_renders_as_text() (duckdb_result.h) -- BEFORE anything is
// executed, so `effective` runs exactly once no matter which way the
// decision goes. There used to be a lexical "is this safe to run a
// second time" gate (duckdb_is_safe_to_rewrap) here; it is gone because
// nothing is ever run a second time any more, so it had nothing left to
// guard -- see the long comment on duckdb_execute_effective's
// definition for the full reasoning, including why a bare DML statement
// can never reach the wrapped-execution path at all (it fails to
// *parse* as `SELECT COLUMNS(*)::VARCHAR FROM (<stmt>)`, so the decision
// falls back to the original statement before anything runs).
DuckDBExecOutcome duckdb_execute_effective(duckdb_connection conn, const std::string& effective);

// Registered as sess->handler_function. `pa` is core's hardcoded global
// (GloSQLite3Server) and is deliberately ignored: the plugin reaches its
// own state through duckdb_context() / duckdb_session_state().
template <typename S>
void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt);

#endif // DUCKDB_SESSION_H
