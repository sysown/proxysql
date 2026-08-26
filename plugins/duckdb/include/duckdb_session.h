#ifndef __DUCKDB_SESSION_H
#define __DUCKDB_SESSION_H

#include "duckdb.h"

#include <cstddef>
#include <cstdint>

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

// Registered as sess->handler_function. `pa` is core's hardcoded global
// (GloSQLite3Server) and is deliberately ignored: the plugin reaches its
// own state through duckdb_context() / duckdb_session_state().
template <typename S>
void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt);

#endif // __DUCKDB_SESSION_H
