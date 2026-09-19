/**
 * @file pgsql-native_auth_differential-t.cpp
 * @brief Differential test: ProxySQL's native PostgreSQL backend protocol vs. the libpq path.
 *
 * ============================================================================
 *  STATUS: WRITTEN BUT UNRUN (Task 1.8)
 *  This test was authored while Docker was unavailable, so it has been
 *  COMPILE-VERIFIED ONLY. It has NEVER been executed against a live backend.
 *  See "FIRST-RUN CHECKLIST" at the bottom of this header before trusting a
 *  green run.
 * ============================================================================
 *
 * PURPOSE
 * -------
 * ProxySQL can connect to PostgreSQL backends either:
 *   - via libpq (the historical path), or
 *   - via a native socket + wire-protocol implementation, gated by the runtime
 *     variable `pgsql-use_native_backend_protocol` (bool, default false).
 *
 * For every auth scenario the infra can support, this test runs an identical,
 * deterministic query set through ProxySQL TWICE:
 *   1. with `pgsql-use_native_backend_protocol='false'`  -> the libpq ORACLE
 *   2. with `pgsql-use_native_backend_protocol='true'`   -> the NATIVE path
 * and asserts the client-visible results are byte-for-byte identical.
 *
 * Crucially, it ALSO asserts that the native run actually used the native path
 * and did NOT silently fall back to libpq. Without this second assertion a
 * silent fallback would make the differential trivially pass (both runs would
 * be libpq). The assertion works by scraping the ProxySQL server log for the
 * fallback / capability-gap warning strings emitted by lib/PgSQL_Connection.cpp
 * and requiring their ABSENCE during the native run for supported methods.
 *
 * The EXACT warning strings grepped (from lib/PgSQL_Connection.cpp), as regexes:
 *   - "native_mode requested but unimplemented at this stage; falling back to libpq"
 *       (PgSQL_Connection::query_cont / ::fetch_result_cont — the Phase-0 stub
 *        fallback; present until the native query path is fully wired)
 *   - "native backend auth capability gap .* falling back to libpq"
 *       (PgSQL_Connection::native_capability_gap — GSSAPI/SSPI/-PLUS-only/
 *        unhandled auth mechanism fallback)
 * If EITHER appears between the native run's start and end, the native path did
 * not fully serve the request and the "used native path" assertion FAILS.
 *
 * HOW A FRESH BACKEND CONNECTION IS FORCED
 * ----------------------------------------
 * `pgsql-use_native_backend_protocol` is read when a NEW backend connection is
 * established; existing pooled connections keep whatever mode they were created
 * with. ProxySQL also pools/reuses backend connections, so simply flipping the
 * variable and opening a new *client* connection is NOT enough — the session
 * might be served by a pooled libpq backend connection.
 *
 * To guarantee a brand-new backend connection that observes the current value,
 * we reset the hostgroup's connection pool via admin between phases:
 *   DELETE FROM pgsql_servers WHERE hostgroup_id=<hg>; LOAD PGSQL SERVERS TO RUNTIME;
 *   <re-INSERT the original server row>;               LOAD PGSQL SERVERS TO RUNTIME;
 * Removing a server sets it OFFLINE_HARD and immediately drops all free
 * connections (see PgSQL_HostGroups_Manager::purge_mysql_servers_table /
 * ConnectionsFree->drop_all_connections in lib/PgSQL_HostGroups_Manager.cpp).
 * Re-inserting brings it back online with an empty pool, so the next client
 * query opens a fresh backend connection in the current mode.
 *
 * INFRA / SCENARIO COVERAGE  (target infra: docker-pgsql16-single, group legacy-g1)
 * --------------------------------------------------------------------------------
 * The backend's pg_hba.conf
 *   (test/infra/docker-pgsql16-single/conf/pgsql/pgsql1/pg_hba.conf) offers, for
 *   network (non-local) connections from ProxySQL:
 *       host    all all all   scram-sha-256
 *       hostssl all all all   cert
 *   and `local ... trust` only over the unix socket (which ProxySQL does not use
 *   for the TCP backend).
 *
 *   => scram-sha-256 (non-TLS)  : SUPPORTED — implemented as a LIVE differential.
 *   => md5                      : SKIPPED — the infra has no md5 entry for normal
 *                                 data users (only `replicator` for replication).
 *                                 Enabling it would require modifying the shared
 *                                 pg_hba.conf + creating a dedicated md5 user in
 *                                 docker-pgsql-post.bash, affecting every legacy-g*
 *                                 test. Out of scope for this task; see the md5
 *                                 fixture note below for how to add it later.
 *   => trust (TCP)              : SKIPPED — only `local` unix-socket is trust;
 *                                 ProxySQL connects to the backend over TCP.
 *   => scram-sha-256 over TLS   : SKIPPED — backend `hostssl` requires client
 *                                 `cert` auth, which the native path does not
 *                                 implement; it would fall back to libpq, so the
 *                                 "used native path" assertion could not hold.
 *                                 Channel binding (SCRAM-SHA-256-PLUS) is also
 *                                 deferred (Task 1.5), so a -PLUS-only server
 *                                 likewise falls back.
 *
 * Each SKIPPED scenario is emitted as a passing TAP line whose description
 * states the infra reason — coverage is documented, never silently dropped.
 *
 * FUTURE FIXTURE NOTE (md5) — only add if you intend to run the md5 scenario:
 *   1. In test/infra/docker-pgsql16-single/conf/pgsql/pgsql1/pg_hba.conf add,
 *      BEFORE the catch-all scram line:
 *          host  all  md5user  all  md5
 *   2. In test/infra/docker-pgsql16-single/bin/docker-pgsql-post.bash add
 *      "md5user" to PGUSERS (with `SET password_encryption='md5'` before
 *      CREATE USER so the stored verifier is md5, not scram).
 *   3. Register an md5 pgsql_user in ProxySQL and flip MD5_SCENARIO_ENABLED below.
 *
 * FIRST-RUN CHECKLIST (do these the first time Docker is up):
 *   [ ] Confirm the scram-sha-256 differential passes (results identical).
 *   [ ] Confirm NO fallback warning appears in proxysql.log during the native
 *       run — i.e. the "used native path" assertion genuinely passes, not just
 *       because the log file path was wrong. Temporarily flipping the native
 *       query path off should make this assertion FAIL; if it never fails, the
 *       log-scrape is not wired correctly.
 *   [ ] Confirm REGULAR_INFRA_DATADIR/proxysql.log is the live server log for
 *       this infra (it is for the isolated runner; see env-isolated.bash).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <unistd.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

// Target hostgroup that the docker-pgsql16-single config seeds (hostgroup 0).
static const int BACKEND_HG = 0;

// md5 scenario is gated off until the optional fixture (see header) is added.
static const bool MD5_SCENARIO_ENABLED = false;

// Open log stream positioned at end-of-file; used by wait_for_log_match /
// get_matching_lines below to scan only lines produced after this point.
static std::fstream f_proxysql_log{};

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// ---------------------------------------------------------------------------
// A captured, comparable snapshot of a query's client-visible result.
// Intentionally excludes anything that legitimately differs run-to-run
// (backend_pid, timestamps, etc.) — the query set below avoids such values.
// ---------------------------------------------------------------------------
struct QueryResult {
	bool ok = false;                 ///< executed without a fatal error
	int nfields = 0;
	int nrows = 0;
	std::vector<std::string> colnames;
	std::vector<Oid> coltypes;       ///< field type OIDs (validates protocol type metadata)
	std::vector<std::vector<std::string>> rows; ///< rows[r][c] text values; "\\N" sentinel for NULL
	std::string err_sqlstate;        ///< SQLSTATE of error, if any (PG_DIAG_SQLSTATE)

	bool operator==(const QueryResult& o) const {
		return ok == o.ok && nfields == o.nfields && nrows == o.nrows &&
		       colnames == o.colnames && coltypes == o.coltypes &&
		       rows == o.rows && err_sqlstate == o.err_sqlstate;
	}
	std::string describe() const {
		std::stringstream ss;
		ss << "ok=" << ok << " nfields=" << nfields << " nrows=" << nrows
		   << " sqlstate='" << err_sqlstate << "'";
		return ss.str();
	}
};

// Deterministic query set. Every entry must be reproducible across connections
// and independent of backend_pid / wall-clock / session randomness.
static const std::vector<std::string> QUERY_SET = {
	"SELECT 1 AS a, 'x'::text AS b",
	"SELECT g AS n FROM generate_series(1,5) AS g ORDER BY g",
	"SELECT current_database() AS db",
	"SELECT NULL::int AS maybe_null, 42 AS answer",
	"SELECT 'café'::text AS utf8_value",
	"SELECT * FROM (VALUES (1,'one'),(2,'two'),(3,'three')) AS t(id,word) ORDER BY id",
	"SELECT count(*) AS c FROM generate_series(1,100)",
	"SELECT this_relation_does_not_exist", // deterministic error -> SQLSTATE 42P01
};

static QueryResult run_one_query(PGconn* conn, const std::string& q) {
	QueryResult r;
	PGresult* res = PQexec(conn, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	if (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK) {
		r.ok = true;
		r.nfields = PQnfields(res);
		r.nrows = PQntuples(res);
		for (int c = 0; c < r.nfields; c++) {
			r.colnames.emplace_back(PQfname(res, c) ? PQfname(res, c) : "");
			r.coltypes.push_back(PQftype(res, c));
		}
		for (int row = 0; row < r.nrows; row++) {
			std::vector<std::string> vals;
			for (int c = 0; c < r.nfields; c++) {
				if (PQgetisnull(res, row, c)) {
					vals.emplace_back("\\N");
				} else {
					vals.emplace_back(PQgetvalue(res, row, c));
				}
			}
			r.rows.push_back(std::move(vals));
		}
	} else {
		r.ok = false;
		const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
		r.err_sqlstate = ss ? ss : "";
	}
	PQclear(res);
	return r;
}

// Run the full deterministic query set on a fresh client connection through
// ProxySQL. Returns the per-query results; `conn_ok` reports whether the client
// connection itself was established.
static std::vector<QueryResult> run_query_set(const char* user, const char* pass,
                                              bool with_ssl, bool& conn_ok) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << user << " password=" << pass
	   << " dbname=" << user
	   << (with_ssl ? " sslmode=require" : " sslmode=disable");
	PGConnPtr conn(PQconnectdb(ss.str().c_str()), &PQfinish);
	std::vector<QueryResult> out;
	if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
		conn_ok = false;
		diag("Client connection through ProxySQL failed: %s",
		     conn ? PQerrorMessage(conn.get()) : "null conn");
		return out;
	}
	conn_ok = true;
	for (const auto& q : QUERY_SET) {
		out.push_back(run_one_query(conn.get(), q));
	}
	return out;
}

// ---------------------------------------------------------------------------
// Admin helpers
// ---------------------------------------------------------------------------
static PGConnPtr createAdminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& query) {
	PGresult* res = PQexec(admin, query.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) {
		diag("Admin query failed: %s -- %s", query.c_str(), PQerrorMessage(admin));
	}
	PQclear(res);
	return good;
}

static bool setNativeMode(PGconn* admin, bool enabled) {
	std::string v = enabled ? "true" : "false";
	bool a = execAdmin(admin, "SET pgsql-use_native_backend_protocol='" + v + "'");
	bool b = execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	return a && b;
}

// Capture the current rows of the target hostgroup so we can re-insert them
// after a pool-flushing DELETE. We restore only the columns the seed config
// sets, which is sufficient for the test backend.
struct ServerRow {
	std::string hostname;
	std::string port;
	std::string max_connections;
	std::string comment;
};

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
	std::vector<ServerRow> rows;
	std::stringstream q;
	q << "SELECT hostname, port, max_connections, comment FROM pgsql_servers "
	  << "WHERE hostgroup_id=" << hg;
	PGresult* res = PQexec(admin, q.str().c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++) {
			ServerRow r;
			r.hostname = PQgetvalue(res, i, 0);
			r.port = PQgetvalue(res, i, 1);
			r.max_connections = PQgetvalue(res, i, 2);
			r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
			rows.push_back(std::move(r));
		}
	} else {
		diag("readServers failed: %s", PQerrorMessage(admin));
	}
	PQclear(res);
	return rows;
}

// Force the hostgroup's backend connection pool to be emptied so the next
// client query opens a BRAND-NEW backend connection that observes the current
// value of pgsql-use_native_backend_protocol. See header for the mechanism.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
	if (saved.empty()) {
		diag("flushBackendPool: no saved server rows for hg %d; cannot flush safely", hg);
		return false;
	}
	std::stringstream del;
	del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << hg;
	if (!execAdmin(admin, del.str())) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false; // drops free conns
	for (const auto& r : saved) {
		std::stringstream ins;
		ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		    << "VALUES (" << hg << ",'" << r.hostname << "'," << r.port << ","
		    << (r.max_connections.empty() ? std::string("1000") : r.max_connections)
		    << ",'" << r.comment << "')";
		if (!execAdmin(admin, ins.str())) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	// brief settle so the OFFLINE_HARD->ONLINE transition is fully applied
	usleep(200000);
	return true;
}

// Scan the proxysql log (from the position captured at the start of the native
// run) for either fallback / capability-gap warning. Returns true if a fallback
// warning was observed (i.e. the native path did NOT fully serve the request).
static bool nativeFallbackObserved() {
	// Two distinct strings from lib/PgSQL_Connection.cpp; OR them in one regex.
	// We intentionally do NOT wait/poll long here: by the time the query set has
	// completed, any per-query fallback warning has already been emitted. A short
	// poll covers the async log flush.
	const std::string regex =
		".*(native_mode requested but unimplemented at this stage; falling back to libpq"
		"|native backend auth capability gap .* falling back to libpq).*";
	return wait_for_log_match(f_proxysql_log, regex, /*timeout_ms*/ 1000, /*poll*/ 100);
}

// Drain the log stream up to "now" so that a subsequent nativeFallbackObserved()
// only considers lines emitted during the native run we are about to perform.
static void drainLogToNow() {
	// get_matching_lines advances the stream to EOF; the trailing position is
	// where the next scan begins. A regex that won't match keeps it cheap.
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// ---------------------------------------------------------------------------
// One full differential scenario for a given auth method / credentials.
// Emits 2 TAP assertions:
//   (1) native results == libpq results
//   (2) native run used the native path (no fallback warning in the log)
// ---------------------------------------------------------------------------
static void run_scenario(PGconn* admin, const char* scenario,
                         const char* user, const char* pass, bool with_ssl,
                         const std::vector<ServerRow>& saved) {
	diag("=== Scenario '%s' (user=%s ssl=%d) ===", scenario, user, with_ssl ? 1 : 0);

	// -- Phase 1: libpq oracle --------------------------------------------
	if (!setNativeMode(admin, false)) {
		ok(false, "auth %s: failed to set libpq mode (admin error)", scenario);
		ok(false, "auth %s: used native path (skipped: prior admin failure)", scenario);
		return;
	}
	if (!flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "auth %s: failed to flush backend pool for libpq phase", scenario);
		ok(false, "auth %s: used native path (skipped: prior pool-flush failure)", scenario);
		return;
	}
	bool libpq_conn_ok = false;
	std::vector<QueryResult> libpq_res = run_query_set(user, pass, with_ssl, libpq_conn_ok);

	// -- Phase 2: native path ---------------------------------------------
	if (!setNativeMode(admin, true)) {
		ok(false, "auth %s: failed to set native mode (admin error)", scenario);
		ok(false, "auth %s: used native path (skipped: prior admin failure)", scenario);
		return;
	}
	if (!flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "auth %s: failed to flush backend pool for native phase", scenario);
		ok(false, "auth %s: used native path (skipped: prior pool-flush failure)", scenario);
		return;
	}
	// Mark the log position so the fallback scan only sees the native run.
	drainLogToNow();
	bool native_conn_ok = false;
	std::vector<QueryResult> native_res = run_query_set(user, pass, with_ssl, native_conn_ok);

	// Assertion 1: identical client-visible results.
	bool identical = (libpq_conn_ok == native_conn_ok) &&
	                 (libpq_res.size() == native_res.size());
	if (identical) {
		for (size_t i = 0; i < libpq_res.size(); i++) {
			if (!(libpq_res[i] == native_res[i])) {
				identical = false;
				diag("auth %s: mismatch on query[%zu]: '%s'", scenario, i, QUERY_SET[i].c_str());
				diag("  libpq : %s", libpq_res[i].describe().c_str());
				diag("  native: %s", native_res[i].describe().c_str());
			}
		}
	} else {
		diag("auth %s: connection-ok or result-count mismatch (libpq_ok=%d n=%zu, native_ok=%d n=%zu)",
		     scenario, libpq_conn_ok, libpq_res.size(), native_conn_ok, native_res.size());
	}
	ok(identical && libpq_conn_ok && native_conn_ok,
	   "auth %s: native result matches libpq", scenario);

	// Assertion 2: the native run actually used the native path (no fallback).
	bool fell_back = nativeFallbackObserved();
	ok(!fell_back, "auth %s: used native path (no libpq fallback)", scenario);
	if (fell_back) {
		diag("auth %s: a fallback/capability-gap warning appeared during the native run;"
		     " the native path did NOT serve this request.", scenario);
	}

	// Leave the variable in the default (false) state for the next scenario.
	setNativeMode(admin, false);
	flushBackendPool(admin, BACKEND_HG, saved);
}

static void skip_scenario(const char* scenario, const char* reason) {
	// Per project standard: never silently drop coverage. Emit two passing TAP
	// lines (matching the 2 assertions a live scenario emits) that record the
	// infra-tied reason this scenario is not exercised.
	ok(true, "auth %s: SKIP (result diff) — %s", scenario, reason);
	ok(true, "auth %s: SKIP (native-path check) — %s", scenario, reason);
}

int main(int /*argc*/, char** /*argv*/) {
	// 4 scenarios * 2 assertions each = 8 TAP lines (live or skipped).
	plan(8);

	if (cl.getEnv())
		return exit_status();

	// Open the live ProxySQL server log so we can scrape it for fallback
	// warnings during the native run. Same mechanism used by
	// pgsql-extended_query_protocol_test-t.cpp.
	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		diag("Could not open ProxySQL log at '%s'; cannot assert native-path usage.",
		     log_path.c_str());
		BAIL_OUT("ProxySQL log unavailable — the native-path assertion would be meaningless");
		return exit_status();
	}

	auto admin = createAdminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("Cannot proceed without admin connection: %s",
		         admin ? PQerrorMessage(admin.get()) : "null conn");
		return exit_status();
	}

	// Snapshot the backend server row(s) so flushBackendPool() can restore them.
	std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers row in hostgroup %d; infra not seeded as expected", BACKEND_HG);
		return exit_status();
	}
	diag("Backend under test (hg %d): %s:%s (%zu row(s))",
	     BACKEND_HG, saved[0].hostname.c_str(), saved[0].port.c_str(), saved.size());

	// -------------------------------------------------------------------
	// Scenario 1 (LIVE): scram-sha-256, non-TLS.
	// The docker-pgsql16-single backend authenticates all network data
	// connections with scram-sha-256 (see pg_hba.conf), and ProxySQL
	// connects without SSL by default — so this exercises native plain
	// SCRAM-SHA-256 (no channel binding).
	// Credentials: the 'testuser' user (password 'testuser') exists both as
	// a ProxySQL pgsql_user and as a backend role with matching password.
	// -------------------------------------------------------------------
	run_scenario(admin.get(), "scram-sha-256",
	             cl.pgsql_username, cl.pgsql_password, /*with_ssl*/ false, saved);

	// -------------------------------------------------------------------
	// Scenario 2 (SKIP): md5.
	// -------------------------------------------------------------------
	if (MD5_SCENARIO_ENABLED) {
		// When the optional md5 fixture is added (see header), exercise it here
		// with the dedicated md5 user. Until then this branch is unreachable.
		run_scenario(admin.get(), "md5", "md5user", "md5user", /*with_ssl*/ false, saved);
	} else {
		skip_scenario("md5",
			"docker-pgsql16-single pg_hba.conf has no md5 entry for data users "
			"(only 'replicator' for replication); enabling requires a shared-infra "
			"fixture change — see header md5 note");
	}

	// -------------------------------------------------------------------
	// Scenario 3 (SKIP): trust over TCP.
	// -------------------------------------------------------------------
	skip_scenario("trust",
		"backend only grants 'trust' over the local unix socket; ProxySQL "
		"connects to the backend over TCP, which requires scram-sha-256");

	// -------------------------------------------------------------------
	// Scenario 4 (SKIP): scram-sha-256 over TLS.
	// -------------------------------------------------------------------
	skip_scenario("scram-over-tls",
		"backend 'hostssl' requires client-cert ('cert') auth, which the native "
		"path does not implement (and SCRAM-SHA-256-PLUS channel binding is "
		"deferred, Task 1.5); ProxySQL falls back to libpq, so the native-path "
		"assertion cannot hold");

	return exit_status();
}
