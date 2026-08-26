#include "duckdb_session.h"
#include "duckdb_result.h"
#include "sqlite3db.h"

#include "proxysql.h"
#include "MySQL_Session.h"
#include "PgSQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"
#include "MySQL_Protocol.h"
#include "PgSQL_Protocol.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <type_traits>

namespace {

// Uppercases, trims, and collapses internal runs of whitespace to one
// space, so "  select   @@VERSION " becomes "SELECT @@VERSION".
std::string normalize(const char* sql, size_t len) {
	std::string out;
	out.reserve(len);
	bool in_space = true;   // true so leading whitespace is dropped
	for (size_t i = 0; i < len && sql[i] != '\0'; i++) {
		const unsigned char c = static_cast<unsigned char>(sql[i]);
		if (std::isspace(c)) {
			if (!in_space) { out.push_back(' '); in_space = true; }
		} else {
			out.push_back(static_cast<char>(std::toupper(c)));
			in_space = false;
		}
	}
	while (!out.empty() && out.back() == ' ') out.pop_back();
	return out;
}

} // namespace

DuckDBIntercept duckdb_classify_query(const char* sql, size_t len) {
	if (sql == nullptr || len == 0) return DuckDBIntercept::none;
	const std::string q = normalize(sql, len);
	if (q.empty()) return DuckDBIntercept::none;

	if (q == "SELECT @@VERSION" || q == "SELECT VERSION()")
		return DuckDBIntercept::version;
	if (q == "SELECT DATABASE()" || q == "SELECT CURRENT_DATABASE()")
		return DuckDBIntercept::database;
	if (q == "SHOW TABLES")     return DuckDBIntercept::show_tables;
	if (q == "SHOW DATABASES" || q == "SHOW SCHEMAS")
		return DuckDBIntercept::show_databases;
	// Session-state statements clients send unprompted. DuckDB has no
	// equivalent; accepting them silently is what SQLite3_Server does.
	if (q.rfind("SET ", 0) == 0)  return DuckDBIntercept::ok_noop;
	return DuckDBIntercept::none;
}

SQLite3_result* duckdb_build_intercept_result(DuckDBIntercept kind) {
	switch (kind) {
	case DuckDBIntercept::version: {
		SQLite3_result* r = new SQLite3_result(1);
		r->add_column_definition(SQLITE_TEXT, "version");
		const char* v = duckdb_library_version();
		const char* row[1] = { v != nullptr ? v : "duckdb" };
		r->add_row(row);
		return r;
	}
	case DuckDBIntercept::database: {
		SQLite3_result* r = new SQLite3_result(1);
		r->add_column_definition(SQLITE_TEXT, "DATABASE()");
		const char* row[1] = { "memory" };
		r->add_row(row);
		return r;
	}
	case DuckDBIntercept::show_tables:
	case DuckDBIntercept::show_databases:
		// Answered by rewriting to DuckDB SQL in the handler, not here.
		return nullptr;
	case DuckDBIntercept::none:
	case DuckDBIntercept::ok_noop:
	default:
		return nullptr;
	}
}

DuckDBSessionState& duckdb_session_state() {
	static thread_local DuckDBSessionState state {};
	return state;
}

// `show_tables` / `show_databases` are answered by rewriting to DuckDB SQL
// against information_schema so they return live data rather than a
// canned row.

// --- duckdb_send_result: private overload pair -----------------------
//
// Declared here, above duckdb_session_handler, because the template calls
// them and there is no dependent-name lookup to find a definition that
// only appears later in the file (C++ two-phase lookup resolves
// non-dependent calls -- these overloads are picked purely on the
// (non-template) session pointer type -- at the point of the template
// definition, not at instantiation).

void duckdb_send_result(MySQL_Session* sess, SQLite3_result* r, char* err,
                        int affected, const char* /*sql*/) {
	sess->SQLite3_to_MySQL(r, err, affected, &sess->client_myds->myprot);
}

void duckdb_send_result(PgSQL_Session* sess, SQLite3_result* r, char* err,
                        int affected, const char* sql) {
	// `sql` matters: SQLite3_to_Postgres derives the CommandComplete tag
	// from its first whitespace-delimited word. It must always be the
	// ORIGINAL client sql, never a rewritten/wrapped query -- callers of
	// this overload must respect that.
	//
	// PSarrayOUT is already a PtrSizeArray* (include/PgSQL_Data_Stream.h),
	// so it is passed as-is: `&sess->client_myds->PSarrayOUT` would be a
	// PtrSizeArray**, which does not convert to the PtrSizeArray*
	// SQLite3_to_Postgres() expects.
	SQLite3_to_Postgres(sess->client_myds->PSarrayOUT, r, err, affected, sql);
}

// --- error emitters ----------------------------------------------------

void duckdb_send_mysql_error(MySQL_Session* sess, uint16_t code,
                             const char* sqlstate, const char* msg) {
	MySQL_Protocol* myprot = &sess->client_myds->myprot;
	MySQL_Data_Stream* myds = myprot->get_myds();
	myds->DSS = STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true, NULL, NULL, 1, code, sqlstate, msg);
	myds->DSS = STATE_SLEEP;
}

// Deliberately does NOT reuse SQLite3_to_Postgres's error branch: that
// path hardcodes SQLSTATE 28000 (invalid_authorization_specification),
// which is wrong for a syntax/malformed-packet/no-connection error. Keeping
// our own emitter avoids a core change and lets each call site pass the
// SQLSTATE that actually applies.
void duckdb_send_pgsql_error(PgSQL_Session* sess, const char* sqlstate,
                             const char* msg) {
	PG_pkt pkt(64);
	pkt.write_generic('E', "cscscsc",
		'S', "ERROR",
		'C', sqlstate,
		'M', msg, 0);
	// PSarrayOUT is already a PtrSizeArray* -- see the comment on the
	// duckdb_send_result(PgSQL_Session*, ...) overload above.
	pkt.to_PtrSizeArray(sess->client_myds->PSarrayOUT);
	pkt.write_ReadyForQuery('I');
	pkt.to_PtrSizeArray(sess->client_myds->PSarrayOUT);
}

// --- the templated handler ---------------------------------------------

template <typename S>
void duckdb_session_handler(S* sess, void* pa, PtrSize_t* pkt) {
	(void)pa;   // core passes GloSQLite3Server; the plugin ignores it.

	std::string sql;
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		// Skip the 4-byte header and the 1-byte command.
		if (pkt->size <= sizeof(mysql_hdr) + 1) {
			duckdb_send_mysql_error(sess, 1064, "42000", "Malformed packet");
			return;
		}
		const size_t len = pkt->size - sizeof(mysql_hdr) - 1;
		sql.assign((const char*)pkt->ptr + sizeof(mysql_hdr) + 1, len);
	} else {
		pgsql_hdr hdr {};
		if (sess->client_myds->myprot.get_header((unsigned char*)pkt->ptr, pkt->size, &hdr) == false) {
			duckdb_send_pgsql_error(sess, "08P01", "Malformed packet");
			return;
		}
		switch (hdr.type) {
		case PG_PKT_STARTUP_V2:
		case PG_PKT_STARTUP:
		case PG_PKT_CANCEL:
		case PG_PKT_SSLREQ:
		case PG_PKT_GSSENCREQ:
			duckdb_send_pgsql_error(sess, "0A000", "Unsupported query type");
			return;
		default:
			break;
		}
		if (hdr.data.size < 2 || hdr.data.ptr == nullptr ||
		    ((const char*)hdr.data.ptr)[hdr.data.size - 1] != '\0') {
			duckdb_send_pgsql_error(sess, "08P01", "Malformed query packet");
			return;
		}
		sql.assign((const char*)hdr.data.ptr, hdr.data.size - 1);
	}

	const DuckDBIntercept kind = duckdb_classify_query(sql.c_str(), sql.size());
	std::string effective = sql;
	switch (kind) {
	case DuckDBIntercept::show_tables:
		effective = "SELECT table_name FROM information_schema.tables "
		            "WHERE table_schema='main'";
		break;
	case DuckDBIntercept::show_databases:
		effective = "SELECT DISTINCT table_schema AS \"Database\" "
		            "FROM information_schema.tables";
		break;
	case DuckDBIntercept::version:
	case DuckDBIntercept::database: {
		SQLite3_result* r = duckdb_build_intercept_result(kind);
		duckdb_send_result(sess, r, nullptr, 0, sql.c_str());
		delete r;
		return;
	}
	case DuckDBIntercept::ok_noop:
		duckdb_send_result(sess, nullptr, nullptr, 0, sql.c_str());
		return;
	case DuckDBIntercept::none:
	default:
		break;
	}

	DuckDBSessionState& st = duckdb_session_state();
	if (st.conn == nullptr) {
		if constexpr (std::is_same_v<S, MySQL_Session>)
			duckdb_send_mysql_error(sess, 1105, "HY000", "No DuckDB connection for this session");
		else
			duckdb_send_pgsql_error(sess, "08003", "No DuckDB connection for this session");
		return;
	}

	duckdb_result res;
	if (duckdb_query(st.conn, effective.c_str(), &res) != DuckDBSuccess) {
		const char* msg = duckdb_result_error(&res);
		std::string copy = msg != nullptr ? msg : "DuckDB query failed";
		duckdb_destroy_result(&res);
		if constexpr (std::is_same_v<S, MySQL_Session>)
			duckdb_send_mysql_error(sess, 1064, "42000", copy.c_str());
		else
			// 42601 (syntax_error) rather than SQLite3_to_Postgres's
			// hardcoded 28000 -- see the comment on duckdb_send_pgsql_error.
			duckdb_send_pgsql_error(sess, "42601", copy.c_str());
		return;
	}

	// DDL/DML in DuckDB 1.4.5 does NOT produce a zero-column result --
	// CREATE TABLE, SET, INSERT/UPDATE/DELETE all return a 1-column
	// "Count" result (see plugins/duckdb/include/duckdb_result.h). The
	// real dispatch signal is duckdb_result_return_type(), which must be
	// checked BEFORE conversion, or a CREATE TABLE would be sent to the
	// client as a one-row resultset instead of an OK/CommandComplete.
	const duckdb_result_type rtype = duckdb_result_return_type(res);

	if (rtype == DUCKDB_RESULT_TYPE_NOTHING) {
		const int affected = 0;
		duckdb_destroy_result(&res);
		duckdb_send_result(sess, nullptr, nullptr, affected, sql.c_str());
		return;
	}
	if (rtype == DUCKDB_RESULT_TYPE_CHANGED_ROWS) {
		const int affected = static_cast<int>(duckdb_rows_changed(&res));
		duckdb_destroy_result(&res);
		duckdb_send_result(sess, nullptr, nullptr, affected, sql.c_str());
		return;
	}

	// rtype == DUCKDB_RESULT_TYPE_QUERY_RESULT from here on.
	//
	// duckdb_value_varchar() (used by duckdb_result_to_sqlite3()) cannot
	// render 11+ column types (LIST, STRUCT, MAP, ARRAY, UNION, UUID,
	// ENUM, BIT, TIMESTAMP_S/MS/NS, ...) -- it silently converts them to
	// a null field, indistinguishable from a genuine SQL NULL. When any
	// column of this result is such a type, re-run the query wrapped as
	// `SELECT COLUMNS(*)::VARCHAR FROM (<effective sql>)`, which casts
	// every column (nested values included, e.g. `[1, 2, 3]`) to a
	// renderable VARCHAR, and convert THAT result instead.
	//
	// `effective`, not the original `sql`, is what gets wrapped: for the
	// show_tables/show_databases intercepts `sql` is client syntax
	// ("SHOW TABLES") that isn't valid DuckDB SQL, while `effective` is
	// the DuckDB statement that was actually just executed successfully.
	//
	// Two caveats, both intentional:
	//  - The wrap renames duplicate column names (`SELECT 1 AS a, 2 AS a`
	//    -> `a`, `a_1`), which is why we only wrap when a column actually
	//    needs it -- `SELECT * FROM a JOIN b` sharing a column name is
	//    common and must stay unwrapped.
	//  - This re-executes the query a second time on this path.
	//
	// If the wrapped re-query itself fails, we fall back to sending the
	// ORIGINAL (NULL-rendering) result rather than erroring out --
	// degraded output beats no output for a query that DID succeed.
	if (duckdb_result_has_unrenderable_column(&res)) {
		const std::string wrapped =
			"SELECT COLUMNS(*)::VARCHAR FROM (" + effective + ")";
		duckdb_result res2;
		if (duckdb_query(st.conn, wrapped.c_str(), &res2) == DuckDBSuccess) {
			duckdb_destroy_result(&res);
			SQLite3_result* out = duckdb_result_to_sqlite3(&res2);
			duckdb_destroy_result(&res2);
			duckdb_send_result(sess, out, nullptr, 0, sql.c_str());
			delete out;
			return;
		}
		// Wrapped re-query failed (e.g. a type COLUMNS(*)::VARCHAR can't
		// cast) -- fall back to the original, possibly NULL-rendering
		// result rather than erroring on a query that already succeeded.
		duckdb_destroy_result(&res2);
	}

	SQLite3_result* out = duckdb_result_to_sqlite3(&res);
	duckdb_destroy_result(&res);
	duckdb_send_result(sess, out, nullptr, 0, sql.c_str());
	delete out;
}

template void duckdb_session_handler<MySQL_Session>(MySQL_Session*, void*, PtrSize_t*);
template void duckdb_session_handler<PgSQL_Session>(PgSQL_Session*, void*, PtrSize_t*);
