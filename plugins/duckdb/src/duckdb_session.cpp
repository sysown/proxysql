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
	while (!out.empty() && out.back() == ';') {
		out.pop_back();
		while (!out.empty() && out.back() == ' ') out.pop_back();
	}
	return out;
}

bool is_client_compatibility_set(const std::string& q) {
	std::string compact;
	compact.reserve(q.size());
	for (char c : q) {
		if (c != ' ') compact.push_back(c);
	}
	if (compact == "SETAUTOCOMMIT=0" || compact == "SETAUTOCOMMIT=1")
		return true;
	return q.rfind("SET NAMES ", 0) == 0 && q.find(';') == std::string::npos;
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
	if (q == "SHOW DATABASES") return DuckDBIntercept::show_databases;
	if (q == "SHOW SCHEMAS")   return DuckDBIntercept::show_schemas;
	// Client-compatibility statements DuckDB does not implement. Other SET
	// statements are DuckDB configuration and must reach the engine.
	if (is_client_compatibility_set(q)) return DuckDBIntercept::ok_noop;
	return DuckDBIntercept::none;
}

SQLite3_result* duckdb_build_intercept_result(DuckDBIntercept kind, const char* database_name) {
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
		const char* name = "memory";
		if (database_name != nullptr && database_name[0] != '\0' &&
		    std::strcmp(database_name, ":memory:") != 0) {
			name = database_name;
		}
		const char* row[1] = { name };
		r->add_row(row);
		return r;
	}
	case DuckDBIntercept::show_tables:
	case DuckDBIntercept::show_databases:
	case DuckDBIntercept::show_schemas:
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

DuckDBPgsqlAction duckdb_pgsql_message_action(DuckDBSessionState& state, char type) {
	if (state.pgsql_extended_error) {
		if (type == 'S') {
			state.pgsql_extended_error = false;
			return DuckDBPgsqlAction::send_ready;
		}
		return DuckDBPgsqlAction::discard;
	}
	if (type == 'P' || type == 'B' || type == 'C' || type == 'D' || type == 'E') {
		state.pgsql_extended_error = true;
		return DuckDBPgsqlAction::send_error;
	}
	if (type == 'H') return DuckDBPgsqlAction::discard;
	if (type == 'S') return DuckDBPgsqlAction::send_ready;
	return DuckDBPgsqlAction::process;
}

const char* duckdb_pgsql_sqlstate(duckdb_error_type type, const std::string& message) {
	switch (type) {
	case DUCKDB_ERROR_PARSER:
	case DUCKDB_ERROR_SYNTAX:
		return "42601";
	case DUCKDB_ERROR_OUT_OF_RANGE:
	case DUCKDB_ERROR_DECIMAL:
		return "22003";
	case DUCKDB_ERROR_CONVERSION:
		return "22018";
	case DUCKDB_ERROR_DIVIDE_BY_ZERO:
		return "22012";
	case DUCKDB_ERROR_TRANSACTION:
		return "25000";
	case DUCKDB_ERROR_NOT_IMPLEMENTED:
	case DUCKDB_ERROR_MISSING_EXTENSION:
	case DUCKDB_ERROR_AUTOLOAD:
		return "0A000";
	case DUCKDB_ERROR_CONSTRAINT:
		return "23000";
	case DUCKDB_ERROR_CONNECTION:
		return "08000";
	case DUCKDB_ERROR_NETWORK:
		return "08006";
	case DUCKDB_ERROR_IO:
		return "58030";
	case DUCKDB_ERROR_INTERRUPT:
		return "57014";
	case DUCKDB_ERROR_OUT_OF_MEMORY:
		return "53200";
	case DUCKDB_ERROR_PERMISSION:
		return "42501";
	case DUCKDB_ERROR_SETTINGS:
	case DUCKDB_ERROR_INVALID_INPUT:
	case DUCKDB_ERROR_PARAMETER_NOT_RESOLVED:
	case DUCKDB_ERROR_PARAMETER_NOT_ALLOWED:
		return "22023";
	default:
		// duckdb_prepare_error() has no companion type accessor. Preserve the
		// one reliable prepare-time category exposed in its message prefix.
		if (message.rfind("Parser Error:", 0) == 0 ||
		    message.rfind("Syntax Error:", 0) == 0)
			return "42601";
		return "XX000";
	}
}

uint16_t duckdb_mysql_errno(duckdb_error_type type, const std::string& message) {
	switch (type) {
	case DUCKDB_ERROR_PARSER:
	case DUCKDB_ERROR_SYNTAX:
		return 1064;
	case DUCKDB_ERROR_OUT_OF_RANGE:
	case DUCKDB_ERROR_DECIMAL:
		return 1264;
	case DUCKDB_ERROR_CONVERSION:
		return 1366;
	case DUCKDB_ERROR_DIVIDE_BY_ZERO:
		return 1365;
	case DUCKDB_ERROR_TRANSACTION:
		return 1180;
	case DUCKDB_ERROR_NOT_IMPLEMENTED:
	case DUCKDB_ERROR_MISSING_EXTENSION:
	case DUCKDB_ERROR_AUTOLOAD:
		return 1235;
	case DUCKDB_ERROR_CONSTRAINT:
		return 1062;
	case DUCKDB_ERROR_CONNECTION:
	case DUCKDB_ERROR_NETWORK:
		return 2013;
	case DUCKDB_ERROR_IO:
		return 1028;
	case DUCKDB_ERROR_INTERRUPT:
		return 1317;
	case DUCKDB_ERROR_OUT_OF_MEMORY:
		return 1037;
	case DUCKDB_ERROR_PERMISSION:
		return 1142;
	case DUCKDB_ERROR_SETTINGS:
	case DUCKDB_ERROR_INVALID_INPUT:
	case DUCKDB_ERROR_PARAMETER_NOT_RESOLVED:
	case DUCKDB_ERROR_PARAMETER_NOT_ALLOWED:
		return 1525;
	default:
		if (message.rfind("Parser Error:", 0) == 0 ||
		    message.rfind("Syntax Error:", 0) == 0)
			return 1064;
		return 1105;
	}
}

const char* duckdb_mysql_sqlstate(duckdb_error_type type, const std::string& message) {
	switch (type) {
	case DUCKDB_ERROR_PARSER:
	case DUCKDB_ERROR_SYNTAX:
		return "42000";
	case DUCKDB_ERROR_OUT_OF_RANGE:
	case DUCKDB_ERROR_DECIMAL:
		return "22003";
	case DUCKDB_ERROR_CONVERSION:
		return "22018";
	case DUCKDB_ERROR_DIVIDE_BY_ZERO:
		return "22012";
	case DUCKDB_ERROR_TRANSACTION:
		return "25000";
	case DUCKDB_ERROR_NOT_IMPLEMENTED:
	case DUCKDB_ERROR_MISSING_EXTENSION:
	case DUCKDB_ERROR_AUTOLOAD:
		return "0A000";
	case DUCKDB_ERROR_CONSTRAINT:
		return "23000";
	case DUCKDB_ERROR_CONNECTION:
	case DUCKDB_ERROR_NETWORK:
		return "08S01";
	case DUCKDB_ERROR_INTERRUPT:
		return "70100";
	case DUCKDB_ERROR_OUT_OF_MEMORY:
		return "HY001";
	case DUCKDB_ERROR_PERMISSION:
		return "42000";
	case DUCKDB_ERROR_SETTINGS:
	case DUCKDB_ERROR_INVALID_INPUT:
	case DUCKDB_ERROR_PARAMETER_NOT_RESOLVED:
	case DUCKDB_ERROR_PARAMETER_NOT_ALLOWED:
		return "HY000";
	default:
		if (message.rfind("Parser Error:", 0) == 0 ||
		    message.rfind("Syntax Error:", 0) == 0)
			return "42000";
		return "HY000";
	}
}

namespace {

enum class DuckDBTxnVerb { none, begin, commit, rollback };

DuckDBTxnVerb classify_txn_verb(const std::string& sql) {
	const std::string q = normalize(sql.c_str(), sql.size());
	if (q.rfind("ROLLBACK TO", 0) == 0) return DuckDBTxnVerb::none;
	if (q == "BEGIN" || q.rfind("BEGIN ", 0) == 0 ||
	    q == "START TRANSACTION" || q.rfind("START TRANSACTION", 0) == 0) {
		return DuckDBTxnVerb::begin;
	}
	if (q == "COMMIT" || q.rfind("COMMIT ", 0) == 0 ||
	    q == "END" || q.rfind("END ", 0) == 0) {
		return DuckDBTxnVerb::commit;
	}
	if (q == "ROLLBACK" || q.rfind("ROLLBACK ", 0) == 0 ||
	    q == "ABORT" || q.rfind("ABORT ", 0) == 0) {
		return DuckDBTxnVerb::rollback;
	}
	return DuckDBTxnVerb::none;
}

void apply_txn_outcome(DuckDBSessionState& st, DuckDBTxnVerb verb, bool ok) {
	if (verb == DuckDBTxnVerb::begin && ok) {
		st.pgsql_txn_status = 'T';
	} else if ((verb == DuckDBTxnVerb::commit || verb == DuckDBTxnVerb::rollback) && ok) {
		st.pgsql_txn_status = 'I';
	} else if (!ok && st.pgsql_txn_status == 'T') {
		st.pgsql_txn_status = 'E';
	}
}

} // namespace

char duckdb_pgsql_transaction_status(duckdb_connection conn) {
	if (conn == nullptr) return 'I';
	return duckdb_session_state().pgsql_txn_status;
}

// `show_tables` / `show_databases` are answered by rewriting to DuckDB SQL
// against information_schema so they return live data rather than a
// canned row.

namespace {

// Strips statement-terminating `;` characters even when trailing SQL
// comments follow them. Semicolons inside strings/comments or before more
// executable SQL are left alone. Confirmed by probe:
// wrapping a statement with a trailing `;` in
// `SELECT COLUMNS(*)::VARCHAR FROM (<sql>)` is a DuckDB parser error at
// the `;` -- and almost every CLI client sends a trailing `;`, so
// leaving it in place would silently defeat the C3 re-query for the most
// common input shape there is.
std::string trim_trailing_semicolons(const std::string& sql) {
	std::string out = sql;
	for (;;) {
		enum class ScanState { normal, single_quote, double_quote, line_comment, block_comment };
		ScanState state = ScanState::normal;
		size_t block_depth = 0;
		size_t last_code = std::string::npos;
		for (size_t i = 0; i < out.size(); i++) {
			const char c = out[i];
			const char next = i + 1 < out.size() ? out[i + 1] : '\0';
			switch (state) {
			case ScanState::normal:
				if (c == '-' && next == '-') {
					state = ScanState::line_comment;
					i++;
				} else if (c == '/' && next == '*') {
					state = ScanState::block_comment;
					block_depth = 1;
					i++;
				} else if (c == '\'') {
					last_code = i;
					state = ScanState::single_quote;
				} else if (c == '"') {
					last_code = i;
					state = ScanState::double_quote;
				} else if (!std::isspace(static_cast<unsigned char>(c))) {
					last_code = i;
				}
				break;
			case ScanState::single_quote:
				last_code = i;
				if (c == '\'' && next == '\'') {
					last_code = ++i;
				} else if (c == '\'') {
					state = ScanState::normal;
				}
				break;
			case ScanState::double_quote:
				last_code = i;
				if (c == '"' && next == '"') {
					last_code = ++i;
				} else if (c == '"') {
					state = ScanState::normal;
				}
				break;
			case ScanState::line_comment:
				if (c == '\n' || c == '\r') state = ScanState::normal;
				break;
			case ScanState::block_comment:
				if (c == '/' && next == '*') {
					block_depth++;
					i++;
				} else if (c == '*' && next == '/') {
					i++;
					if (--block_depth == 0) state = ScanState::normal;
				}
				break;
			}
		}
		if (last_code == std::string::npos || out[last_code] != ';') break;
		out.erase(last_code, 1);
	}
	return out;
}

} // namespace

// --- duckdb_execute_effective: DDL/DML/QUERY_RESULT dispatch (C2), and
// the unrenderable-column rewrap decided BEFORE execution (C3) ---------
//
// Runs `effective` and translates the outcome into a DuckDBExecOutcome
// with no protocol-specific code in it, so the templated handler below
// stays a thin packet-in/response-out shim and this logic can be
// exercised directly against a live duckdb_connection in tests.
//
// C3 background: duckdb_result_to_sqlite3() preserves the established
// direct-conversion allowlist and does not render 11+ column types (LIST,
// STRUCT, MAP, ARRAY, UNION, UUID, ENUM, BIT, TIMESTAMP_S/MS/NS, ...) --
// it silently converts them to a null field, indistinguishable from a
// genuine SQL NULL. The fix is to run `SELECT COLUMNS(*)::VARCHAR FROM
// (<effective sql>)` instead, which casts every column (nested values
// included, e.g. `[1, 2, 3]`) to a renderable VARCHAR.
//
// An earlier version of this function executed `effective` first via
// duckdb_query(), inspected the REAL result for an unrenderable column,
// and -- if found -- ran the wrapped SQL as a SECOND, separate
// duckdb_query() call, guarded by a lexical "is this safe to run twice"
// check. That was wrong: `effective` is not necessarily side-effect-free
// just because it starts with SELECT/WITH. `SELECT [nextval('s')]`
// returns a LIST (unrenderable) and advances the sequence on its FIRST
// execution; the lexical gate passed it (no RETURNING, starts with
// SELECT) and re-ran it, silently advancing the sequence a second time
// and returning the wrong value to the client. The same problem applies
// to any volatile function (random(), now(), uuid(), ...): a lexical
// "looks like a read" check cannot tell side-effect-free apart from
// side-effect-free-looking.
//
// The fix here is structural rather than lexical: decide whether the
// rewrap is needed by inspecting a *prepared* statement's column types
// (duckdb_prepared_statement_column_type(), via
// duckdb_type_renders_as_text() in duckdb_result.h) -- preparing a
// statement parses and binds it but does NOT execute it (confirmed by
// probe: preparing `SELECT [nextval('s')]` does not advance the
// sequence) -- and only THEN execute exactly one of the two candidate
// statements (original or wrapped), via duckdb_execute_prepared().
// `effective` is therefore executed exactly once no matter which way
// the decision goes, which is what makes the old lexical safety gate
// (duckdb_is_safe_to_rewrap) unnecessary: it existed solely to stop a
// second execution that this design no longer performs, so it has been
// removed rather than kept as inert legacy code.
//
// A prepared statement must always be destroyed via
// duckdb_destroy_prepare(), even when duckdb_prepare() itself failed
// (documented in duckdb.h above duckdb_prepare()) -- every prepare below
// is paired with a destroy on every path.
DuckDBExecOutcome duckdb_execute_effective(duckdb_connection conn, const std::string& effective) {
	DuckDBExecOutcome outcome;
	const DuckDBTxnVerb verb = classify_txn_verb(effective);
	auto finish = [&]() {
		apply_txn_outcome(duckdb_session_state(), verb, outcome.ok);
		return outcome;
	};

	duckdb_prepared_statement stmt = nullptr;
	if (duckdb_prepare(conn, effective.c_str(), &stmt) != DuckDBSuccess) {
		// duckdb_prepare_error() must be read BEFORE duckdb_destroy_prepare()
		// -- like duckdb_result_error(), the message lives inside the
		// prepared statement and does not survive its destruction.
		const char* msg = duckdb_prepare_error(stmt);
		outcome.ok = false;
		outcome.error = msg != nullptr ? msg : "DuckDB prepare failed";
		duckdb_destroy_prepare(&stmt);
		return finish();
	}

	// Inspect the prepared statement's output schema -- no execution has
	// happened yet -- for any column outside the direct-conversion
	// allowlist. DDL/DML's 1-column "Count" result (see duckdb_result.h) is
	// always BIGINT, which renders fine, so this is false for every
	// CREATE/SET/plain INSERT/UPDATE/DELETE; it can only be true for a
	// genuine QUERY_RESULT-shaped statement (a SELECT, or DML with
	// RETURNING).
	bool needs_wrap = false;
	const idx_t ncols = duckdb_prepared_statement_column_count(stmt);
	for (idx_t c = 0; c < ncols; c++) {
		if (!duckdb_type_renders_as_text(duckdb_prepared_statement_column_type(stmt, c))) {
			needs_wrap = true;
			break;
		}
	}

	// `exec_stmt` is whichever prepared statement we end up actually
	// running -- exactly one, exactly once, below.
	duckdb_prepared_statement exec_stmt = stmt;

	if (needs_wrap) {
		// The subquery is wrapped with newlines around `effective`
		// (`FROM (\n<sql>\n)`), not straight concatenation: a trailing
		// `-- comment` immediately before a `)` would otherwise swallow
		// it, breaking the wrap silently. Trailing `;` (almost every CLI
		// client sends one) is stripped first for the same reason -- a
		// `;` inside the subquery is itself a parser error.
		const std::string trimmed = trim_trailing_semicolons(effective);
		const std::string wrapped =
			"SELECT COLUMNS(*)::VARCHAR FROM (\n" + trimmed + "\n)";

		duckdb_prepared_statement wrap_stmt = nullptr;
		if (duckdb_prepare(conn, wrapped.c_str(), &wrap_stmt) == DuckDBSuccess) {
			// The wrap parses -- which on its own proves `trimmed` is
			// valid FROM-clause subquery content, i.e. a read-shaped
			// statement, since DuckDB's grammar rejects a bare
			// INSERT/UPDATE/DELETE (even with RETURNING) in that
			// position (confirmed by probe: "syntax error at or near
			// INTO") and this build has no writable-CTE support either.
			// Discard the original prepared statement WITHOUT ever
			// executing it, and run the wrap instead.
			duckdb_destroy_prepare(&stmt);
			exec_stmt = wrap_stmt;
		} else {
			// The wrap doesn't parse (e.g. RETURNING DML, which cannot
			// legally sit inside a FROM-clause subquery in this DuckDB
			// grammar). Fall back to the ORIGINAL prepared statement --
			// still not executed yet either way -- and accept the
			// degraded (NULL-rendering) output for the unrenderable
			// column: degraded output beats no output for a query that
			// is about to succeed.
			duckdb_destroy_prepare(&wrap_stmt);
		}
	}

	duckdb_result res;
	const duckdb_state exec_state = duckdb_execute_prepared(exec_stmt, &res);
	duckdb_destroy_prepare(&exec_stmt);
	if (exec_state != DuckDBSuccess) {
		const char* msg = duckdb_result_error(&res);
		outcome.ok = false;
		outcome.error = msg != nullptr ? msg : "DuckDB query failed";
		outcome.error_type = duckdb_result_error_type(&res);
		duckdb_destroy_result(&res);
		return finish();
	}

	// DDL/DML in DuckDB 1.4.5 does NOT produce a zero-column result --
	// CREATE TABLE, SET, INSERT/UPDATE/DELETE all return a 1-column
	// "Count" result (see plugins/duckdb/include/duckdb_result.h). The
	// real dispatch signal is duckdb_result_return_type(), which must be
	// checked BEFORE conversion, or a CREATE TABLE would be sent to the
	// client as a one-row resultset instead of an OK/CommandComplete.
	const duckdb_result_type rtype = duckdb_result_return_type(res);

	if (rtype == DUCKDB_RESULT_TYPE_NOTHING) {
		outcome.has_resultset = false;
		outcome.affected_rows = 0;
		duckdb_destroy_result(&res);
		return finish();
	}
	if (rtype == DUCKDB_RESULT_TYPE_CHANGED_ROWS) {
		outcome.has_resultset = false;
		outcome.affected_rows = static_cast<int>(duckdb_rows_changed(&res));
		duckdb_destroy_result(&res);
		return finish();
	}

	// rtype == DUCKDB_RESULT_TYPE_QUERY_RESULT: either the original
	// query (renderable, or unrenderable-but-fell-back-to-degraded), or
	// the wrap (every column now VARCHAR). Either way it already ran
	// exactly once above, so just convert it.
	outcome.has_resultset = true;
	std::string conversion_error;
	outcome.result = duckdb_result_to_sqlite3(&res, &conversion_error);
	duckdb_destroy_result(&res);
	if (!conversion_error.empty()) {
		outcome.ok = false;
		outcome.has_resultset = false;
		outcome.error_type = DUCKDB_ERROR_OUT_OF_RANGE;
		outcome.error = conversion_error;
	}
	return finish();
}

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
	SQLite3_to_Postgres(sess->client_myds->PSarrayOUT, r, err, affected, sql,
		true, duckdb_pgsql_transaction_status(duckdb_session_state().conn));
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
namespace {

void duckdb_send_pgsql_error_response(PgSQL_Session* sess, const char* sqlstate,
                                      const char* msg) {
	PG_pkt pkt(64);
	pkt.write_generic('E', "cscscsc",
		'S', "ERROR",
		'C', sqlstate,
		'M', msg, 0);
	// PSarrayOUT is already a PtrSizeArray* -- see the comment on the
	// duckdb_send_result(PgSQL_Session*, ...) overload above.
	pkt.to_PtrSizeArray(sess->client_myds->PSarrayOUT);
}

void duckdb_send_pgsql_ready(PgSQL_Session* sess) {
	PG_pkt pkt(16);
	pkt.write_ReadyForQuery(
		duckdb_pgsql_transaction_status(duckdb_session_state().conn));
	pkt.to_PtrSizeArray(sess->client_myds->PSarrayOUT);
}

} // namespace

void duckdb_send_pgsql_error(PgSQL_Session* sess, const char* sqlstate,
                             const char* msg) {
	duckdb_send_pgsql_error_response(sess, sqlstate, msg);
	duckdb_send_pgsql_ready(sess);
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
		switch (duckdb_pgsql_message_action(duckdb_session_state(), hdr.type)) {
		case DuckDBPgsqlAction::discard:
			return;
		case DuckDBPgsqlAction::send_error:
			duckdb_send_pgsql_error_response(sess, "0A000",
				"DuckDB plugin does not support the PostgreSQL extended-query protocol");
			return;
		case DuckDBPgsqlAction::send_ready:
			duckdb_send_pgsql_ready(sess);
			return;
		case DuckDBPgsqlAction::process:
			break;
		}
		switch (hdr.type) {
		case 'Q':
			break;
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
		effective = "SELECT database_name AS \"Database\" "
		            "FROM duckdb_databases() WHERE NOT internal "
		            "ORDER BY database_name";
		break;
	case DuckDBIntercept::show_schemas:
		effective = "SELECT DISTINCT schema_name AS \"Schema\" "
		            "FROM information_schema.schemata "
		            "ORDER BY schema_name";
		break;
	case DuckDBIntercept::version:
	case DuckDBIntercept::database: {
		const char* dbname = (kind == DuckDBIntercept::database)
			? duckdb_session_state().database_name.c_str()
			: nullptr;
		SQLite3_result* r = duckdb_build_intercept_result(kind, dbname);
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

	// All DDL/DML/QUERY_RESULT dispatch (C2) and the unrenderable-column
	// re-query with its double-execution safety gate (C3) live in
	// duckdb_execute_effective(), which is protocol-agnostic and directly
	// testable against a live duckdb_connection. `sql` (the ORIGINAL
	// client text), not `effective`, is what goes to duckdb_send_result:
	// for PgSQL, SQLite3_to_Postgres derives its CommandComplete tag from
	// the first word of whatever we pass it.
	const DuckDBExecOutcome outcome = duckdb_execute_effective(st.conn, effective);
	if (!outcome.ok) {
		if constexpr (std::is_same_v<S, MySQL_Session>)
			duckdb_send_mysql_error(sess,
				duckdb_mysql_errno(outcome.error_type, outcome.error),
				duckdb_mysql_sqlstate(outcome.error_type, outcome.error),
				outcome.error.c_str());
		else
			duckdb_send_pgsql_error(sess,
				duckdb_pgsql_sqlstate(outcome.error_type, outcome.error),
				outcome.error.c_str());
		return;
	}
	if (outcome.has_resultset) {
		duckdb_send_result(sess, outcome.result, nullptr, 0, sql.c_str());
		delete outcome.result;
	} else {
		duckdb_send_result(sess, nullptr, nullptr, outcome.affected_rows, sql.c_str());
	}
}

template void duckdb_session_handler<MySQL_Session>(MySQL_Session*, void*, PtrSize_t*);
template void duckdb_session_handler<PgSQL_Session>(PgSQL_Session*, void*, PtrSize_t*);
