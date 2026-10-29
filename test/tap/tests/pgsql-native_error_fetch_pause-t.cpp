/**
 * @file pgsql-native_error_fetch_pause-t.cpp
 * @brief An ErrorResponse that crosses the fetch-pause threshold must still be
 *        followed by its ReadyForQuery, on the native backend protocol (issue #6410).
 *
 * WHAT WAS BROKEN
 * ---------------
 * The native result drain paused, once enough bytes had moved in one event, before
 * taking the next message. The handler then ended the query cycle on any recorded
 * error. When the message that crossed the threshold was an ErrorResponse, the
 * drain paused between the 'E' and its 'Z', and the cycle ended with the 'Z' still
 * in the framer and a result that was never READY:
 *   - single statement: PgSQL_Result_to_PgSQL_wire() hit assert(resultset_completed)
 *     and SIGABRTed the whole proxy (asserts stay active in release builds);
 *   - multi-statement: the client hung waiting for ReadyForQuery, the connection went
 *     back to the pool with the 'Z' unread, and the next client to get it failed with
 *     08P01 "backend answered the query with no command outcome";
 *   - extended protocol: the backend still owed a ReadyForQuery, so the connection
 *     was judged broken and the client was disconnected.
 * PostgreSQL echoes the input into the error text, so the client controls the size
 * of the 'E': `SELECT repeat('x', N)::int` makes one as large as it wants, and at the
 * default settings 40 MB crosses the 32 MB pause threshold on its own.
 *
 * CASES (each run once per transport: plain, then TLS on both legs)
 * -----
 *   A. threshold_resultset_size=1024 (pause at 8 KiB): an 8000-byte error (below the
 *      threshold, control) and a 9000-byte one (above it) both return 22P02, and the
 *      same connection then answers SELECT 1.
 *   B. default threshold (4 MiB -> pause at 32 MiB): a 40 MiB error returns 22P02.
 *   C. multi-statement at threshold 1024: TUPLES_OK, TUPLES_OK, FATAL_ERROR and then
 *      the end of the results within 5 s; afterwards more fresh clients than there are
 *      free backend connections each run a query with no 08P01, so no pooled
 *      connection was left holding an unread ReadyForQuery.
 *   D. throttle (max_bytes_per_second_to_client=1000, ratio=1 -> pause at 100 bytes):
 *      a query on a missing table returns 42P01.
 *   E. extended protocol at threshold 1024: PQexecParams with a 9000-byte error
 *      returns 22P02, the client stays CONNECTION_OK and its next PQexecParams works.
 * After every case both the admin interface and a new client must answer SELECT 1,
 * i.e. the proxy is still running. Per transport, proxysql.log must contain no
 * assertion failure, no "no command outcome", no "Detected a broken connection" and
 * no hit of the fail-safe that replaced the assert.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single), hostgroup 0.
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <chrono>
#include <poll.h>
#include <unistd.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql-native_transport.h"

CommandLine cl;

static const int BACKEND_HG = 0;
// Default pgsql-threshold_resultset_size; the fetch pauses past 8x this.
static const char* DEFAULT_THRESHOLD = "4194304";

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr createAdminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createClientConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=" << native_client_sslmode()
	   << " connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& query) {
	PGresult* res = PQexec(admin, query.c_str());
	const ExecStatusType st = PQresultStatus(res);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("Admin failed: %s -- %s", query.c_str(), PQerrorMessage(admin));
	PQclear(res);
	return good;
}

static std::string scalar(PGconn* conn, const std::string& query) {
	PGresult* res = PQexec(conn, query.c_str());
	std::string out;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		out = PQgetvalue(res, 0, 0);
	PQclear(res);
	return out;
}

static std::string adminVariable(PGconn* admin, const std::string& name) {
	return scalar(admin, "SELECT variable_value FROM global_variables WHERE variable_name='" + name + "'");
}

// Sets pgsql-<name>=<value> for each pair and loads them in one go.
static bool setPgsqlVariables(PGconn* admin, const std::vector<std::pair<std::string, std::string>>& vars) {
	for (const auto& v : vars) {
		if (!execAdmin(admin, "SET pgsql-" + v.first + "='" + v.second + "'")) return false;
	}
	return execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

struct ServerRow {
	std::string hostname, port, max_connections, use_ssl, comment;
};

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin, ("SELECT hostname, port, max_connections, use_ssl, comment FROM pgsql_servers "
		"WHERE hostgroup_id=" + std::to_string(hg)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++) {
			ServerRow r;
			r.hostname = PQgetvalue(res, i, 0);
			r.port = PQgetvalue(res, i, 1);
			r.max_connections = PQgetvalue(res, i, 2);
			r.use_ssl = PQgetvalue(res, i, 3);
			r.comment = PQgetisnull(res, i, 4) ? "" : PQgetvalue(res, i, 4);
			rows.push_back(std::move(r));
		}
	}
	PQclear(res);
	return rows;
}

// Deletes and re-inserts the server rows, so no backend connection created under a
// previous setting survives: native_mode is fixed per backend connection when it is
// created. use_ssl < 0 restores each row's saved value.
static bool recreateServers(PGconn* admin, int hg, const std::vector<ServerRow>& saved, int use_ssl) {
	if (saved.empty()) return false;
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		std::stringstream ins;
		ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
		    << "VALUES (" << hg << ",'" << r.hostname << "'," << r.port << ","
		    << (r.max_connections.empty() ? std::string("1000") : r.max_connections) << ","
		    << (use_ssl < 0 ? r.use_ssl : std::to_string(use_ssl)) << ",'" << r.comment << "')";
		if (!execAdmin(admin, ins.str())) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

static std::string sqlstate_of(const PGresult* res) {
	const char* s = res ? PQresultErrorField(res, PG_DIAG_SQLSTATE) : nullptr;
	return s ? s : "";
}

// Runs `q` and reports its status and SQLSTATE. Error messages can be 40 MiB here,
// so only their first bytes are ever printed.
struct Outcome {
	ExecStatusType status = PGRES_FATAL_ERROR;
	std::string sqlstate;
	std::string value;
};

static Outcome run_query(PGconn* c, const std::string& q) {
	Outcome o;
	PGresult* res = PQexec(c, q.c_str());
	o.status = PQresultStatus(res);
	o.sqlstate = sqlstate_of(res);
	if (o.status == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		o.value = PQgetvalue(res, 0, 0);
	if (o.status != PGRES_TUPLES_OK && o.status != PGRES_COMMAND_OK) {
		diag("  '%.60s' -> %s sqlstate='%s' msg='%.120s'", q.c_str(), PQresStatus(o.status),
		     o.sqlstate.c_str(), PQerrorMessage(c));
	}
	PQclear(res);
	return o;
}

static Outcome run_params(PGconn* c, const char* q, int nparams, const char* const* values) {
	Outcome o;
	PGresult* res = PQexecParams(c, q, nparams, nullptr, values, nullptr, nullptr, 0);
	o.status = PQresultStatus(res);
	o.sqlstate = sqlstate_of(res);
	if (o.status == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		o.value = PQgetvalue(res, 0, 0);
	if (o.status != PGRES_TUPLES_OK && o.status != PGRES_COMMAND_OK) {
		diag("  params '%.60s' -> %s sqlstate='%s' msg='%.120s'", q, PQresStatus(o.status),
		     o.sqlstate.c_str(), PQerrorMessage(c));
	}
	PQclear(res);
	return o;
}

static bool select1_ok(PGconn* c) {
	const Outcome o = run_query(c, "SELECT 1");
	return o.status == PGRES_TUPLES_OK && o.value == "1";
}

// The proxy survived: the admin interface still answers, and so does a brand new
// client. The admin check opens its own connection too, because an admin connection
// kept open across a crash would only report the crash, not that the proxy is back.
static void ok_proxy_alive(const std::string& tag) {
	auto admin = createAdminConn();
	const bool admin_ok = admin && PQstatus(admin.get()) == CONNECTION_OK && select1_ok(admin.get());
	auto client = createClientConn();
	const bool client_ok = client && PQstatus(client.get()) == CONNECTION_OK && select1_ok(client.get());
	ok(admin_ok && client_ok, "%s: proxy still alive (admin SELECT 1: %s, new client SELECT 1: %s)",
	   tag.c_str(), admin_ok ? "ok" : "FAILED", client_ok ? "ok" : "FAILED");
}

// Sends `q` as one simple-query message and collects every result until
// PQgetResult() returns NULL. `finished` is false if that did not happen within
// `timeout_ms` -- the hang the issue describes.
struct MultiOutcome {
	std::vector<ExecStatusType> statuses;
	std::vector<std::string> sqlstates;
	bool finished = false;
};

static MultiOutcome run_multi(PGconn* c, const std::string& q, int timeout_ms) {
	MultiOutcome out;
	if (!PQsendQuery(c, q.c_str())) {
		diag("  PQsendQuery failed: %s", PQerrorMessage(c));
		return out;
	}
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	for (;;) {
		while (PQisBusy(c)) {
			const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
				deadline - std::chrono::steady_clock::now()).count();
			if (left <= 0) {
				diag("  no end of results within %d ms", timeout_ms);
				return out;
			}
			struct pollfd pfd { PQsocket(c), POLLIN, 0 };
			if (poll(&pfd, 1, (int)left) < 0) return out;
			if (!PQconsumeInput(c)) {
				diag("  PQconsumeInput failed: %s", PQerrorMessage(c));
				return out;
			}
		}
		PGresult* res = PQgetResult(c);
		if (res == nullptr) {
			out.finished = true;
			return out;
		}
		out.statuses.push_back(PQresultStatus(res));
		out.sqlstates.push_back(sqlstate_of(res));
		PQclear(res);
	}
}

static int free_connections(PGconn* admin, int hg) {
	const std::string v = scalar(admin,
		"SELECT COALESCE(SUM(ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
	return v.empty() ? 0 : atoi(v.c_str());
}

static std::fstream f_proxysql_log{};

static void seekLogToEnd() {
	f_proxysql_log.clear();
	f_proxysql_log.seekg(0, std::ios::end);
}

static const std::string THRESHOLD_1024 = "1024";

static void case_A(const std::string& tr) {
	const std::string tag = tr + " A (threshold 1024)";
	auto c = createClientConn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) diag("%s: client connect failed", tag.c_str());
	const Outcome below = run_query(c.get(), "SELECT repeat('x',8000)::int");
	ok(below.status == PGRES_FATAL_ERROR && below.sqlstate == "22P02",
	   "%s: 8000-byte error, below the pause threshold, returns 22P02 (got %s '%s')",
	   tag.c_str(), PQresStatus(below.status), below.sqlstate.c_str());
	const Outcome above = run_query(c.get(), "SELECT repeat('x',9000)::int");
	ok(above.status == PGRES_FATAL_ERROR && above.sqlstate == "22P02",
	   "%s: 9000-byte error, above the pause threshold, returns 22P02 (got %s '%s')",
	   tag.c_str(), PQresStatus(above.status), above.sqlstate.c_str());
	ok(select1_ok(c.get()), "%s: the same connection answers SELECT 1 afterwards", tag.c_str());
	c.reset();
	ok_proxy_alive(tag);
}

static void case_B(const std::string& tr) {
	const std::string tag = tr + " B (default threshold, 40 MiB error)";
	auto c = createClientConn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) diag("%s: client connect failed", tag.c_str());
	const Outcome big = run_query(c.get(), "SELECT repeat('x',40*1024*1024)::int");
	ok(big.status == PGRES_FATAL_ERROR && big.sqlstate == "22P02",
	   "%s: returns 22P02 (got %s '%s')", tag.c_str(), PQresStatus(big.status), big.sqlstate.c_str());
	ok(select1_ok(c.get()), "%s: the same connection answers SELECT 1 afterwards", tag.c_str());
	c.reset();
	ok_proxy_alive(tag);
}

static void case_C(PGconn* admin, const std::string& tr) {
	const std::string tag = tr + " C (multi-statement, threshold 1024)";
	auto c = createClientConn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) diag("%s: client connect failed", tag.c_str());
	const MultiOutcome m = run_multi(c.get(), "SELECT 1; SELECT 2; SELECT repeat('x',9000)::int", 5000);
	const bool shape = m.finished && m.statuses.size() == 3 &&
		m.statuses[0] == PGRES_TUPLES_OK && m.statuses[1] == PGRES_TUPLES_OK &&
		m.statuses[2] == PGRES_FATAL_ERROR && m.sqlstates[2] == "22P02";
	std::string got;
	for (size_t i = 0; i < m.statuses.size(); i++) {
		got += std::string(i ? ", " : "") + PQresStatus(m.statuses[i]);
		if (!m.sqlstates[i].empty()) got += "(" + m.sqlstates[i] + ")";
	}
	ok(shape, "%s: TUPLES_OK, TUPLES_OK, FATAL_ERROR(22P02), then end of results within 5 s (got [%s]%s)",
	   tag.c_str(), got.c_str(), m.finished ? "" : ", no end of results");
	ok(m.finished && select1_ok(c.get()), "%s: the same connection answers SELECT 1 afterwards", tag.c_str());
	c.reset();

	// Hold every free backend connection at once, plus one, so whichever connection
	// served the multi-statement is handed to a probe. BEGIN binds the backend right
	// away on PostgreSQL, and keeps it until COMMIT.
	usleep(200000);   // pool returns are asynchronous
	const int n_free = free_connections(admin, BACKEND_HG);
	const int n_probes = std::min(n_free + 1, 64);
	std::vector<PGConnPtr> probes;
	int failures = 0;
	std::string first_failure;
	for (int i = 0; i < n_probes; i++) {
		auto p = createClientConn();
		if (!p || PQstatus(p.get()) != CONNECTION_OK) {
			failures++;
			if (first_failure.empty()) first_failure = "connect failed";
			continue;
		}
		const Outcome b = run_query(p.get(), "BEGIN");
		const Outcome s = run_query(p.get(), "SELECT 'probe'");
		if (b.status != PGRES_COMMAND_OK || s.status != PGRES_TUPLES_OK || s.value != "probe") {
			failures++;
			if (first_failure.empty())
				first_failure = (b.status != PGRES_COMMAND_OK ? "BEGIN " + b.sqlstate : "SELECT " + s.sqlstate);
		}
		probes.push_back(std::move(p));
	}
	for (auto& p : probes) run_query(p.get(), "COMMIT");
	probes.clear();
	ok(failures == 0, "%s: %d fresh clients (free backend connections: %d) all succeed, no 08P01 from a "
	   "connection left with an unread ReadyForQuery (%d failed%s%s)",
	   tag.c_str(), n_probes, n_free, failures, first_failure.empty() ? "" : ", first: ", first_failure.c_str());
	ok_proxy_alive(tag);
}

static void case_D(const std::string& tr) {
	const std::string tag = tr + " D (throttle, pause at 100 bytes)";
	auto c = createClientConn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) diag("%s: client connect failed", tag.c_str());
	const Outcome missing = run_query(c.get(), "SELECT * FROM no_such_table_t");
	ok(missing.status == PGRES_FATAL_ERROR && missing.sqlstate == "42P01",
	   "%s: returns 42P01 (got %s '%s')", tag.c_str(), PQresStatus(missing.status), missing.sqlstate.c_str());
	ok(select1_ok(c.get()), "%s: the same connection answers SELECT 1 afterwards", tag.c_str());
	c.reset();
	ok_proxy_alive(tag);
}

static void case_E(const std::string& tr) {
	const std::string tag = tr + " E (extended protocol, threshold 1024)";
	auto c = createClientConn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) diag("%s: client connect failed", tag.c_str());
	const char* params[1] = { "9000" };
	const Outcome err = run_params(c.get(), "SELECT repeat('x',$1::int)::int", 1, params);
	ok(err.status == PGRES_FATAL_ERROR && err.sqlstate == "22P02",
	   "%s: 9000-byte error returns 22P02 (got %s '%s')", tag.c_str(), PQresStatus(err.status), err.sqlstate.c_str());
	ok(PQstatus(c.get()) == CONNECTION_OK, "%s: the client stays connected", tag.c_str());
	const Outcome one = run_params(c.get(), "SELECT 1", 0, nullptr);
	ok(one.status == PGRES_TUPLES_OK && one.value == "1",
	   "%s: the next PQexecParams on the same connection succeeds (got %s '%s')",
	   tag.c_str(), PQresStatus(one.status), one.value.c_str());
	c.reset();
	ok_proxy_alive(tag);
}

// Case assertions: A 4, B 3, C 4, D 3, E 4; plus the log check.
static const int CASE_ASSERTIONS = 4 + 3 + 4 + 3 + 4;
static const int LOG_ASSERTIONS = 1;

int main(int /*argc*/, char** /*argv*/) {
	plan((int)NATIVE_TRANSPORT_COUNT * (NATIVE_TRANSPORT_CHECKS + CASE_ASSERTIONS + LOG_ASSERTIONS));

	if (cl.getEnv())
		return exit_status();

	const std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Could not open ProxySQL log at '%s'", log_path.c_str());
		return exit_status();
	}

	auto admin = createAdminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("Cannot proceed without admin connection: %s", admin ? PQerrorMessage(admin.get()) : "null");
		return exit_status();
	}
	const std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers row in hostgroup %d", BACKEND_HG);
		return exit_status();
	}
	const std::string saved_native = adminVariable(admin.get(), "pgsql-use_native_backend_protocol");
	const std::string saved_threshold = adminVariable(admin.get(), "pgsql-threshold_resultset_size");
	const std::string saved_throttle_bytes = adminVariable(admin.get(), "pgsql-throttle_max_bytes_per_second_to_client");
	const std::string saved_throttle_ratio = adminVariable(admin.get(), "pgsql-throttle_ratio_server_to_client");
	if (saved_native.empty() || saved_threshold.empty() || saved_throttle_bytes.empty() || saved_throttle_ratio.empty()) {
		BAIL_OUT("Cannot read the pgsql variables this test changes");
		return exit_status();
	}
	diag("Backend (hg %d): %s:%s; use_native_backend_protocol=%s threshold_resultset_size=%s "
	     "throttle_max_bytes_per_second_to_client=%s throttle_ratio_server_to_client=%s",
	     BACKEND_HG, saved[0].hostname.c_str(), saved[0].port.c_str(), saved_native.c_str(),
	     saved_threshold.c_str(), saved_throttle_bytes.c_str(), saved_throttle_ratio.c_str());

	auto restore_fetch_vars = [&]() {
		return setPgsqlVariables(admin.get(), {
			{ "threshold_resultset_size", saved_threshold },
			{ "throttle_max_bytes_per_second_to_client", saved_throttle_bytes },
			{ "throttle_ratio_server_to_client", saved_throttle_ratio } });
	};

	for (size_t t = 0; t < NATIVE_TRANSPORT_COUNT; t++) {
		native_transport_select(t);
		const std::string tr = std::string("[") + native_transport_name() + "]";
		seekLogToEnd();

		ok_native_transport(admin.get(), BACKEND_HG,
			[&] {
				return setPgsqlVariables(admin.get(), { { "use_native_backend_protocol", "true" } }) &&
				       recreateServers(admin.get(), BACKEND_HG, saved, native_backend_use_ssl());
			},
			createClientConn, /*check_client*/ true);

		if (!setPgsqlVariables(admin.get(), { { "threshold_resultset_size", THRESHOLD_1024 },
		                                      { "throttle_max_bytes_per_second_to_client", "0" } })) {
			BAIL_OUT("Cannot set threshold_resultset_size=1024");
		}
		case_A(tr);

		if (!setPgsqlVariables(admin.get(), { { "threshold_resultset_size", DEFAULT_THRESHOLD } })) {
			BAIL_OUT("Cannot set the default threshold_resultset_size");
		}
		case_B(tr);

		if (!setPgsqlVariables(admin.get(), { { "threshold_resultset_size", THRESHOLD_1024 } })) {
			BAIL_OUT("Cannot set threshold_resultset_size=1024");
		}
		case_C(admin.get(), tr);

		if (!setPgsqlVariables(admin.get(), { { "threshold_resultset_size", DEFAULT_THRESHOLD },
		                                      { "throttle_max_bytes_per_second_to_client", "1000" },
		                                      { "throttle_ratio_server_to_client", "1" } })) {
			BAIL_OUT("Cannot enable throttling");
		}
		case_D(tr);

		if (!setPgsqlVariables(admin.get(), { { "threshold_resultset_size", THRESHOLD_1024 },
		                                      { "throttle_max_bytes_per_second_to_client", "0" } })) {
			BAIL_OUT("Cannot set threshold_resultset_size=1024");
		}
		case_E(tr);

		restore_fetch_vars();

		// Nothing above may have reached an assertion, a bare-ReadyForQuery refusal, a
		// broken-connection teardown or the fail-safe that replaced the assert.
		const auto bad = get_matching_lines(f_proxysql_log,
			"(Assertion|no command outcome|Detected a broken connection|ended without ReadyForQuery)");
		for (size_t i = 0; i < bad.second.size() && i < 5; i++) {
			diag("  log: %.200s", std::get<LINE_MATCH_T::LINE>(bad.second[i]).c_str());
		}
		ok(bad.second.empty(), "%s proxysql.log has no assertion, 'no command outcome', broken-connection "
		   "or fail-safe line (%zu found)", tr.c_str(), bad.second.size());
	}

	native_transport_select(0);
	restore_fetch_vars();
	setPgsqlVariables(admin.get(), { { "use_native_backend_protocol", saved_native } });
	recreateServers(admin.get(), BACKEND_HG, saved, -1);

	return exit_status();
}
