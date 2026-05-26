/**
 * @file pgsql-reg_test_5801_options_startup_param-t.cpp
 * @brief Regression test for issue #5801 — the PostgreSQL StartupMessage
 *        `options` parameter ProxySQL sends to a backend.
 *
 * Two defects are covered, both exercised through the real backend-connection
 * code path (PgSQL_Connection::connect_start builds the conninfo,
 * PgSQL_Protocol::process_handshake_response_packet collects untracked
 * parameters). The string ProxySQL actually handed to the backend is read back
 * via `PROXYSQL INTERNAL SESSION` → backends[].conn.pgsql.options, which is
 * PQoptions() on the live backend connection — i.e. exactly what was built.
 *
 *  1. Trailing space (#5801): the options value must not end with whitespace.
 *     PgBouncer rejects a StartupMessage whose `options` value has a trailing space.
 *
 *  2. Untracked-parameter accumulation: when a client passes several
 *     unrecognized parameters via `options=`, all of them must be forwarded.
 *     The previous code overwrote on each iteration, keeping only the last.
 */

#include <unistd.h>
#include <memory>
#include <string>
#include <sstream>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "json.hpp"

using nlohmann::json;

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// Connect to the ProxySQL PgSQL frontend, optionally passing client `options`.
static PGConnPtr connect_backend(const std::string& options) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
	ss << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;
	ss << " sslmode=disable";
	if (!options.empty()) {
		ss << " options='" << options << "'";
	}
	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		diag("Connection failed: %s", PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

static bool exec_ok(PGconn* conn, const char* q) {
	PGresult* res = PQexec(conn, q);
	ExecStatusType st = PQresultStatus(res);
	bool ok_st = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK);
	if (!ok_st) {
		diag("Query '%s' failed: %s", q, PQerrorMessage(conn));
	}
	PQclear(res);
	return ok_st;
}

// Run PROXYSQL INTERNAL SESSION and parse the JSON it returns into `out`.
// Returns false (and leaves `out` untouched) on query or parse failure.
static bool fetch_internal_session(PGconn* conn, json& out) {
	PGresult* res = PQexec(conn, "PROXYSQL INTERNAL SESSION;");
	if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) < 1) {
		diag("PROXYSQL INTERNAL SESSION failed: %s", PQerrorMessage(conn));
		PQclear(res);
		return false;
	}
	const std::string json_str = PQgetvalue(res, 0, 0);
	PQclear(res);
	try {
		out = json::parse(json_str);
		return true;
	} catch (const std::exception& e) {
		diag("JSON parse error: %s", e.what());
		return false;
	}
}

// backends[0].conn.pgsql.options — the PQoptions() string of the backend
// connection this session is attached to (i.e. exactly what connect_start built).
static std::string backend_options(const json& j) {
	try {
		if (!j.contains("backends") || !j["backends"].is_array() || j["backends"].empty())
			return "";
		const auto& b = j["backends"][0];
		if (!b.contains("conn") || !b["conn"].contains("pgsql") || !b["conn"]["pgsql"].contains("options"))
			return "";
		return b["conn"]["pgsql"]["options"].get<std::string>();
	} catch (...) {
		return "";
	}
}

static int session_locked_on_hostgroup(const json& j) {
	try {
		if (j.contains("locked_on_hostgroup")) return j["locked_on_hostgroup"].get<int>();
	} catch (...) {}
	return -2; // distinct from -1 (=not locked) so a parse failure is visible
}

// Assert generic well-formedness shared by every options string ProxySQL builds.
// Always emits exactly 5 assertions (keeps the TAP plan stable even if the
// options string came back empty, e.g. on an infrastructure failure). The
// `present &&` guards short-circuit before back()/front() on an empty string.
static void check_well_formed(const std::string& opts, const char* ctx) {
	const bool present = !opts.empty();
	ok(present, "[%s] backend options string is present (got '%s')", ctx, opts.c_str());
	// The #5801 regression: a trailing space here is exactly what PgBouncer rejects.
	ok(present && opts.back() != ' ', "[%s] options has NO trailing space (issue #5801)", ctx);
	ok(present && opts.front() != ' ', "[%s] options has no leading space", ctx);
	ok(present && opts.find("  ") == std::string::npos, "[%s] options has no double space", ctx);
	ok(present && opts.compare(0, 3, "-c ") == 0, "[%s] options starts with a '-c ' token", ctx);
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environment variables");
		return exit_status();
	}

	plan(
		5 +        // tracked-only: check_well_formed
		1 +        // tracked-only: a tracked var is forwarded
		1 +        // untracked: session locked on hostgroup (untracked path was taken)
		5 +        // untracked: check_well_formed
		3          // untracked: geqo + join_collapse_limit + trailing-space restated
	);         // = 15

	// ---------------------------------------------------------------
	// Case 1: default connection (no client options). ProxySQL still
	// forwards its tracked session variables, so the options string is
	// the pure tracked-variable path — the core #5801 scenario.
	// ---------------------------------------------------------------
	{
		PGConnPtr conn = connect_backend("");
		if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
			BAIL_OUT("Failed to connect to the ProxySQL PgSQL frontend in file %s, line %d", __FILE__, __LINE__);
			return exit_status();
		}
		// Pin the backend to the session (transaction) AND force a brand-new
		// backend connection (create_new_connection=1) so the connection we
		// inspect was built by connect_start for THIS session — never a reused
		// pooled connection whose options another session populated.
		// PROXYSQL INTERNAL SESSION reports backends attached to this session
		// (PgSQL_Session::mybes), not the global connection pool.
		if (!exec_ok(conn.get(), "BEGIN") ||
			!exec_ok(conn.get(), "/* create_new_connection=1 */ SELECT 1")) {
			BAIL_OUT("tracked-only: setup queries failed in file %s, line %d", __FILE__, __LINE__);
			return exit_status();
		}
		json j;
		if (!fetch_internal_session(conn.get(), j)) {
			BAIL_OUT("tracked-only: PROXYSQL INTERNAL SESSION fetch failed in file %s, line %d", __FILE__, __LINE__);
			return exit_status();
		}
		const std::string opts = backend_options(j);
		diag("tracked-only options: '%s'", opts.c_str());
		check_well_formed(opts, "tracked-only");
		ok(opts.find("-c DateStyle=") != std::string::npos,
			"tracked-only: a tracked variable (DateStyle) is forwarded");
		exec_ok(conn.get(), "COMMIT");
	}

	// ---------------------------------------------------------------
	// Case 2: client passes TWO unrecognized parameters via options=.
	// Both must survive into the backend StartupMessage (accumulation),
	// joined by single spaces, with no trailing space.
	// geqo and join_collapse_limit are standard, non-tracked GUCs.
	// ---------------------------------------------------------------
	{
		PGConnPtr conn = connect_backend("-c geqo=off -c join_collapse_limit=8");
		if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
			BAIL_OUT("Failed to connect with untracked options in file %s, line %d", __FILE__, __LINE__);
			return exit_status();
		}
		// Untracked options set lock_hostgroup + create_new_conn, so ProxySQL
		// builds a dedicated backend connection (fresh connect_start) and keeps
		// it attached to this session — exactly the connection we want to read.
		if (!exec_ok(conn.get(), "SELECT 1")) {
			BAIL_OUT("untracked: setup query failed in file %s, line %d", __FILE__, __LINE__);
			return exit_status();
		}
		json j;
		if (!fetch_internal_session(conn.get(), j)) {
			BAIL_OUT("untracked: PROXYSQL INTERNAL SESSION fetch failed in file %s, line %d", __FILE__, __LINE__);
			return exit_status();
		}

		// Guard: prove these parameters actually went through the *untracked*
		// accumulation path. The untracked path sets lock_hostgroup, so the
		// session must be locked on a hostgroup (>= 0). If geqo/join_collapse_limit
		// are ever promoted to tracked variables, there would be no untracked
		// parameters, the session would not lock, and this assertion fails loudly —
		// signalling the maintainer to pick different non-tracked GUCs below.
		ok(session_locked_on_hostgroup(j) >= 0,
			"untracked: session locked on hostgroup, confirming the untracked-parameter path was exercised");

		const std::string opts = backend_options(j);
		diag("untracked options: '%s'", opts.c_str());
		check_well_formed(opts, "untracked");
		ok(opts.find("-c geqo=off") != std::string::npos,
			"untracked: first untracked parameter (geqo) forwarded");
		ok(opts.find("-c join_collapse_limit=8") != std::string::npos,
			"untracked: second untracked parameter (join_collapse_limit) forwarded — accumulation, not overwrite");
		ok(!opts.empty() && opts.back() != ' ',
			"untracked: options has NO trailing space even with untracked tail (issue #5801)");
	}

	return exit_status();
}
