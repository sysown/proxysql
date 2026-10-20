/**
 * @file pgsql-idle_ping_dead_conns-t.cpp
 * @brief The idle ping must really reach the backend: a pooled connection PostgreSQL
 *        ended while it sat idle is dropped before a client gets it, and a healthy one
 *        is kept alive.
 *
 * Every pgsql-ping_interval_server_msec each worker thread pings the free connections
 * idle that long. The ping used to be a stub that always passed, so a backend killed
 * by pg_terminate_backend, idle_session_timeout or a restart went back into the pool
 * and the next client query found it dead. The ping is now an empty query and its
 * ReadyForQuery, in both backend modes.
 *
 * Run for libpq and native mode (when the target has it), each over plaintext and TLS.
 * Each run first checks, from ProxySQL's own record, that the pooled connections really
 * use the mode under test, so the native half cannot pass by testing libpq again.
 *
 *   A. The pings reach the server. pg_stat_activity.state_change of idle pooled
 *      backends moves forward while no client uses them, and they stay pooled.
 *   B. Killed while idle. Every pooled backend is terminated over a direct connection.
 *      The pool drops all of them with no client involved, the proxy logs exactly one
 *      "during ping" line per connection carrying the backend's reason and how long it
 *      sat idle, and fresh clients then succeed.
 *   C. Kept alive (plaintext only, once per mode; needs PostgreSQL 14+). A role with
 *      idle_session_timeout=4s keeps its pooled backends well past 4s, because each
 *      ping restarts the timer.
 *   D. Silent backend (plaintext only, once per mode). A scripted mock backend answers
 *      one query and then reads nothing more, like a host that crashed or a network
 *      cut: the ping gets no reply, the proxy logs one "Ping timeout" line and drops
 *      the connection.
 *   E. Edge cases (plaintext only, once per mode), with the mock scripting the reply
 *      to the ping:
 *      E1  a reply 300 ms late keeps the connection under a 1000 ms timeout;
 *      E2  the same reply drops it once the timeout is lowered to 100 ms at runtime;
 *      E3  ParameterStatus and NoticeResponse ahead of the reply are absorbed;
 *      E4  an ErrorResponse drops the connection and logs the backend's message;
 *      E5  a backend that closes on receiving the ping is dropped;
 *      E6  a reply split into single bytes is still read;
 *      E7  a reply saying a transaction is open keeps the connection out of the pool;
 *      E8  raising the interval at runtime stops the pings, lowering it resumes them;
 *      E9  a server removed while its connection is being pinged ends with that
 *          connection destroyed rather than pooled.
 *
 * The test uses roles and a hostgroup of its own, so killing by role, giving a role a
 * 4 s idle timeout or registering the mock cannot touch any other test. The monitor is
 * off for the run, so its own probes cannot reach the mock. Variables are changed at
 * runtime only.
 */
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"
#include "pgsql_mock_backend.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int   HG       = 0;
static const int   N        = 4;
static const char* USER     = "idle_ping_user";   // phases A and B
static const char* KA_USER  = "idle_ping_ka";     // phase C, idle_session_timeout=4s
static const char* MOCK_USER = "idle_ping_mock";  // phase D, routed to the mock
static const int   MOCK_HG  = 61;
static const char* PASS     = "idle_ping_pass";

static std::fstream f_proxysql_log{};

static void silenceNotices(void*, const char*) {}

static PGConnPtr openConn(const char* h, int p, const char* u, const char* pw, const char* db) {
	std::stringstream ss;
	ss << "host=" << h << " port=" << p << " user=" << u << " password=" << pw;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable connect_timeout=10";
	PGConnPtr c(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (c) PQsetNoticeProcessor(c.get(), &silenceNotices, nullptr);
	return c;
}

static PGConnPtr openAdmin()   { return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, ""); }
static PGConnPtr openBackend() { return openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username, cl.pgsql_server_password, "postgres"); }
static PGConnPtr openClient(const char* user) { return openConn(cl.pgsql_host, cl.pgsql_port, user, PASS, "postgres"); }

static bool execOk(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const ExecStatusType st = PQresultStatus(r);
	const bool ok_ = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok_) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return ok_;
}

static std::string scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		out = PQgetvalue(r, 0, 0);
	PQclear(r);
	return out;
}

// One column, every row.
static std::vector<std::string> column(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::vector<std::string> out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK)
		for (int i = 0; i < PQntuples(r); i++) out.push_back(PQgetvalue(r, i, 0));
	PQclear(r);
	return out;
}

static bool setVar(PGconn* admin, const char* name, const std::string& value) {
	return execOk(admin, std::string("SET ") + name + "='" + value + "'")
		&& execOk(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static std::string runtimeVar(PGconn* admin, const char* name) {
	return scalar(admin, std::string("SELECT variable_value FROM runtime_global_variables WHERE variable_name='") + name + "'");
}

static int poolFree(PGconn* admin, int hg = HG) {
	const std::string n = scalar(admin, "SELECT COALESCE(SUM(ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
	return n.empty() ? -1 : atoi(n.c_str());
}

// Free plus in use. A connection being pinged sits in the used list for the round trip,
// so with no client connected this is the number of connections the pool still holds.
static int poolConns(PGconn* admin, int hg = HG) {
	const std::string n = scalar(admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
	return n.empty() ? -1 : atoi(n.c_str());
}

static int poolConnsWithin(PGconn* admin, int want, int seconds, int hg = HG) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	int last = -1;
	while (true) {
		last = poolConns(admin, hg);
		if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
		usleep(100000);
	}
}

static int poolFreeWithin(PGconn* admin, int want, int seconds) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	int last = -1;
	while (true) {
		last = poolFree(admin);
		if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
		usleep(100000);
	}
}

// OFFLINE_HARD and back empties the pool; re-inserting identical rows would not. Also the
// only way to make a flipped native mode or use_ssl apply: pooled connections keep theirs.
static bool flushPool(PGconn* admin, int hg = HG) {
	std::string prev = scalar(admin, "SELECT status FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg) + " LIMIT 1");
	if (prev.empty()) prev = "ONLINE";
	if (!execOk(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	std::string left;
	while (std::chrono::steady_clock::now() < deadline) {
		left = std::to_string(poolConns(admin, hg));
		if (left == "0") break;
		usleep(100000);
	}
	if (!execOk(admin, "UPDATE pgsql_servers SET status='" + prev + "' WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	return left == "0";
}

// N clients each hold a transaction at the same time, so each needs a backend of its own;
// committing and disconnecting then leaves N connections idle in the pool.
static bool fillPool(PGconn* admin, const char* user) {
	std::vector<PGConnPtr> cs;
	for (int i = 0; i < N; i++) {
		cs.push_back(openClient(user));
		if (PQstatus(cs.back().get()) != CONNECTION_OK) {
			diag("client connect as %s failed: %s", user, PQerrorMessage(cs.back().get()));
			return false;
		}
		if (!execOk(cs.back().get(), "BEGIN") || !execOk(cs.back().get(), "SELECT 1")) return false;
	}
	for (auto& c : cs) if (!execOk(c.get(), "COMMIT")) return false;
	cs.clear();
	return poolFreeWithin(admin, N, 10) == N;
}

static std::string q(const char* s) { return std::string("'") + s + "'"; }

// The backend protocol of every free connection in `hg`, as ProxySQL records it:
// "native", "libpq", or the counts when it is mixed or empty.
static std::string poolMode(PGconn* admin, int hg = HG) {
	PGresult* r = PQexec(admin, ("SELECT pgsql_info FROM stats_pgsql_free_connections WHERE hostgroup=" + std::to_string(hg)).c_str());
	int native = 0, libpq = 0;
	if (PQresultStatus(r) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(r); i++) {
			const std::string info = PQgetvalue(r, i, 0);
			if (info.find("\"native_mode\":true") != std::string::npos) native++;
			else if (info.find("\"native_mode\":false") != std::string::npos) libpq++;
		}
	}
	PQclear(r);
	if (native && !libpq) return "native";
	if (libpq && !native) return "libpq";
	return "native=" + std::to_string(native) + " libpq=" + std::to_string(libpq);
}

static std::vector<std::string> backendPids(PGconn* be, const char* user) {
	return column(be, "SELECT pid FROM pg_stat_activity WHERE usename=" + q(user) + " ORDER BY pid");
}

static int countAlive(PGconn* be, const std::vector<std::string>& pids) {
	std::string in;
	for (const auto& p : pids) in += (in.empty() ? "" : ",") + p;
	const std::string n = scalar(be, "SELECT count(*) FROM pg_stat_activity WHERE pid IN (" + in + ")");
	return n.empty() ? -1 : atoi(n.c_str());
}

static std::fstream::pos_type log_mark = 0;

// Start a new log window: the scans below only see what ProxySQL logs from here on.
static void markLog() {
	f_proxysql_log.clear();
	f_proxysql_log.seekg(0, std::ios::end);
	log_mark = f_proxysql_log.tellg();
}

// Lines matching `re` logged since markLog(). Every scan starts again from the mark:
// get_matching_lines() leaves the stream after its last match, so a second scan
// would otherwise miss lines logged before the first scan's matches.
static std::vector<std::string> logLinesSince(const std::string& re) {
	f_proxysql_log.clear();
	f_proxysql_log.seekg(log_mark);
	std::vector<std::string> out;
	for (const auto& m : get_matching_lines(f_proxysql_log, re).second) out.push_back(std::get<LINE>(m));
	return out;
}

static void cleanupUsers(PGconn* admin, PGconn* be) {
	execOk(admin, std::string("DELETE FROM pgsql_users WHERE username IN (") + q(USER) + "," + q(KA_USER) + "," + q(MOCK_USER) + ")");
	execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
	scalar(be, std::string("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename IN (") + q(USER) + "," + q(KA_USER) + ")");
	execOk(be, std::string("DROP ROLE IF EXISTS ") + USER);
	execOk(be, std::string("DROP ROLE IF EXISTS ") + KA_USER);
}

static bool addProxyUser(PGconn* admin, const char* user, int hg) {
	return execOk(admin, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES (")
		+ q(user) + "," + q(PASS) + ",1," + std::to_string(hg) + ")")
		&& execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
}

static bool createUser(PGconn* admin, PGconn* be, const char* user, const char* role_setting) {
	if (!execOk(be, std::string("CREATE ROLE ") + user + " LOGIN PASSWORD " + q(PASS))) return false;
	if (role_setting && !execOk(be, std::string("ALTER ROLE ") + user + " SET " + role_setting)) return false;
	return addProxyUser(admin, user, HG);
}

// A: idle pooled backends see the pings and stay pooled.
static void phasePingsReachServer(PGconn* admin, PGconn* be, const std::string& tag, bool tls, const char* mode) {
	const bool filled = flushPool(admin) && fillPool(admin, USER);
	const std::vector<std::string> pids = backendPids(be, USER);
	const std::string got_mode = poolMode(admin);
	ok(filled && got_mode == mode, "%s: the pooled connections really are %s (%s)", tag.c_str(), mode, got_mode.c_str());
	if (tls) {
		const std::string n = scalar(be, "SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid)"
			" WHERE a.usename=" + q(USER) + " AND s.ssl");
		ok(filled && n == std::to_string(N), "%s: the %d pooled backends use TLS (%s)", tag.c_str(), N, n.c_str());
	}
	markLog();
	const std::string sc_q = "SELECT string_agg(state_change::text, ',' ORDER BY pid) FROM pg_stat_activity WHERE usename=" + q(USER);
	const std::string before = scalar(be, sc_q);
	sleep(4);  // ping interval is 1 s: several rounds
	const std::string after_changes = scalar(be, "SELECT count(*) FROM pg_stat_activity a WHERE usename=" + q(USER)
		+ " AND state_change > now() - interval '3 seconds'");
	const std::string after = scalar(be, sc_q);
	const int alive = countAlive(be, pids);
	const int pooled = poolConns(admin);
	const auto broken = logLinesSince(".*(Detected a broken connection|Ping timeout).*");
	ok(filled && (int)pids.size() == N && alive == N && pooled == N && before != after
		&& after_changes == std::to_string(N) && broken.empty(),
		"%s: idle pooled backends are pinged and kept (pids=%zu alive=%d pooled=%d recently_active=%s logged=%zu)",
		tag.c_str(), pids.size(), alive, pooled, after_changes.c_str(), broken.size());
}

// B: backends killed while pooled are dropped by the ping, one log line each.
static void phaseKilledWhileIdle(PGconn* admin, PGconn* be, const std::string& tag) {
	const bool filled = flushPool(admin) && fillPool(admin, USER);
	const std::vector<std::string> pids = backendPids(be, USER);
	markLog();
	const std::string killed = scalar(be, "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename=" + q(USER));
	const int left = poolConnsWithin(admin, 0, 10);
	ok(filled && (int)pids.size() == N && killed == std::to_string(N) && left == 0,
		"%s: the pool drops all %d killed backends with no client involved (killed=%s pooled=%d)",
		tag.c_str(), N, killed.c_str(), left);

	int served = 0;
	for (int i = 0; i < N; i++) {
		PGConnPtr c = openClient(USER);
		if (PQstatus(c.get()) == CONNECTION_OK && scalar(c.get(), "SELECT 1") == "1") served++;
	}
	ok(served == N, "%s: %d fresh clients each succeed afterwards (%d)", tag.c_str(), N, served);

	usleep(500000);  // the log is written asynchronously to the SQL that triggers it
	const auto all_broken = logLinesSince(".*Detected a broken connection.*");
	int ping_lines = 0, with_reason = 0, with_idle = 0;
	const std::regex last_used_re("last_used ([0-9]+)ms ago");
	for (const auto& l : all_broken) {
		if (l.find("while during ping") == std::string::npos) continue;
		ping_lines++;
		if (l.find("terminating connection due to administrator command") != std::string::npos) with_reason++;
		std::smatch m;
		if (std::regex_search(l, m, last_used_re) && atoll(m[1].str().c_str()) >= 1000) with_idle++;
	}
	const auto failed_lines = logLinesSince(".*Failed to (consume input|flush data to backend|send query).*");
	for (const auto& l : all_broken) diag("%s", l.c_str());
	ok(ping_lines == N && (int)all_broken.size() == N && with_reason == N && with_idle == N && failed_lines.empty(),
		"%s: exactly one 'during ping' line per killed backend, with its reason and idle time"
		" (ping=%d all=%zu reason=%d idle>=1000ms=%d failed_to=%zu)",
		tag.c_str(), ping_lines, all_broken.size(), with_reason, with_idle, failed_lines.size());
}

// C: the ping restarts the server's idle_session_timeout.
static void phaseKeptAlive(PGconn* admin, PGconn* be, const std::string& tag) {
	const bool filled = flushPool(admin) && fillPool(admin, KA_USER);
	const std::vector<std::string> pids = backendPids(be, KA_USER);
	markLog();
	sleep(10);  // 2.5x the role's idle_session_timeout
	const int alive = countAlive(be, pids);
	const int pooled = poolConns(admin);
	const auto broken = logLinesSince(".*(Detected a broken connection|Ping timeout).*");
	ok(filled && (int)pids.size() == N && alive == N && pooled == N && broken.empty(),
		"%s: backends with idle_session_timeout=4s are still alive after 10s idle (alive=%d pooled=%d logged=%zu)",
		tag.c_str(), alive, pooled, broken.size());
}

// EmptyQueryResponse and ReadyForQuery: what a real server answers to an empty query.
static std::string reply_ok(char txn = 'I') {
	std::string r;
	pgmb_append_msg(r, 'I', "");
	return r + pgmb_ready_for_query(txn);
}

static std::string notice(const std::string& msg) {
	std::string body;
	body += 'S'; body += "NOTICE"; body += '\0';
	body += 'C'; body += "00000"; body += '\0';
	body += 'M'; body += msg; body += '\0';
	body += '\0';
	std::string r;
	pgmb_append_msg(r, 'N', body);
	return r;
}

static bool registerMock(PGconn* admin, const std::string& mock_host, uint16_t port, bool on) {
	const std::string hg = std::to_string(MOCK_HG);
	return execOk(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg)
		&& (!on || execOk(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) VALUES ("
			+ hg + ",'" + mock_host + "'," + std::to_string(port) + ",4,0,'idle ping mock')"))
		&& execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

// D: a backend that stops answering is dropped when the ping gets no reply in time.
//
// The mock answers the client's query with EmptyQueryResponse, a valid reply to any
// query, and is only registered for the seconds a phase needs it.
static void phaseSilentBackend(PGconn* admin, PgSQL_Mock_Backend& mock, const std::string& mock_host, const std::string& tag, const char* mode) {
	std::vector<Step> script = pgmb_script_accept_trust();
	script.push_back(step_expect_query());
	script.push_back(step_send(reply_ok()));
	script.push_back(step_sleep(6000));  // reads nothing more, so the ping's query is never answered
	script.push_back(step_close());
	mock.set_script(script);
	const bool registered = registerMock(admin, mock_host, mock.port(), true);
	bool served = false;
	{
		PGConnPtr c = openClient(MOCK_USER);
		if (PQstatus(c.get()) == CONNECTION_OK) {
			PGresult* r = PQexec(c.get(), "SELECT 1");
			served = PQresultStatus(r) == PGRES_EMPTY_QUERY;
			if (!served) diag("query through the mock: %s", PQresultErrorMessage(r));
			PQclear(r);
		} else {
			diag("client connect to the mock failed: %s", PQerrorMessage(c.get()));
		}
	}
	// The ping can only start once the connection has sat idle for the 1 s interval.
	const int pooled = poolConnsWithin(admin, 1, 5, MOCK_HG);
	const std::string got_mode = poolMode(admin, MOCK_HG);  // read before the ping can start, 1 s from now
	markLog();
	const int left = poolConnsWithin(admin, 0, 5, MOCK_HG);
	usleep(500000);  // the log is written asynchronously
	const auto timeouts = logLinesSince(".*Ping timeout during ping on " + mock_host + ":" + std::to_string(mock.port()) + " .*");
	const auto broken = logLinesSince(".*Detected a broken connection.*");
	for (const auto& l : timeouts) diag("%s", l.c_str());
	const bool unregistered = registerMock(admin, mock_host, mock.port(), false);
	ok(registered && served && pooled == 1 && got_mode == mode && left == 0 && timeouts.size() == 1 && broken.empty() && unregistered,
		"%s: a backend that stops answering is dropped by the ping timeout (served=%d pooled=%d mode=%s left=%d"
		" timeout_lines=%zu broken_lines=%zu)",
		tag.c_str(), served, pooled, got_mode.c_str(), left, timeouts.size(), broken.size());
}

// ---------------------------------------------------------------- E: edge cases

struct MockCase {
	PGconn* admin;
	PgSQL_Mock_Backend& mock;
	const std::string& host;
	const char* mode;
};

// Register the mock with `ping_steps` scripted after the client's query, then run one
// client query so that exactly one connection, in the mode under test, sits in the pool.
static bool startCase(MockCase& f, const std::vector<Step>& ping_steps) {
	std::vector<Step> script = pgmb_script_accept_trust();
	script.push_back(step_expect_query());
	script.push_back(step_send(reply_ok()));
	for (const auto& st : ping_steps) script.push_back(st);
	script.push_back(step_expect_message());  // hold the socket until the proxy lets go of it
	f.mock.set_script(script);
	f.mock.reset_stats();
	if (!registerMock(f.admin, f.host, f.mock.port(), true)) return false;
	bool served = false;
	{
		PGConnPtr c = openClient(MOCK_USER);
		if (PQstatus(c.get()) == CONNECTION_OK) {
			PGresult* r = PQexec(c.get(), "SELECT 1");
			served = PQresultStatus(r) == PGRES_EMPTY_QUERY;
			PQclear(r);
		} else {
			diag("client connect to the mock failed: %s", PQerrorMessage(c.get()));
		}
	}
	markLog();
	if (!served || poolConnsWithin(f.admin, 1, 5, MOCK_HG) != 1) return false;
	const std::string got_mode = poolMode(f.admin, MOCK_HG);  // before the first ping, 1 s from now
	if (got_mode != f.mode) {
		diag("the pooled connection is %s, not %s", got_mode.c_str(), f.mode);
		return false;
	}
	return true;
}

// Wait until the mock has received `n` queries in total; the client's query is the first.
static bool waitQueries(MockCase& f, int n, int seconds) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	while (f.mock.queries_observed() < n && std::chrono::steady_clock::now() < deadline) usleep(50000);
	return f.mock.queries_observed() >= n;
}

static void endCase(MockCase& f) {
	registerMock(f.admin, f.host, f.mock.port(), false);
	poolConnsWithin(f.admin, 0, 5, MOCK_HG);
}

static const char* PING_LINES = ".*(Detected a broken connection|Ping timeout).*";

// The connection survives the ping: the mock got it, and one connection is still pooled
// with nothing logged against it.
static void expectKept(MockCase& f, const std::string& tag, const char* what, int reply_ms) {
	const bool pinged = waitQueries(f, 2, 5);
	usleep((reply_ms + 400) * 1000);
	const int pooled = poolConns(f.admin, MOCK_HG);
	const auto lines = logLinesSince(PING_LINES);
	for (const auto& l : lines) diag("%s", l.c_str());
	ok(pinged && pooled == 1 && lines.empty(), "%s: %s keeps the connection (pinged=%d pooled=%d logged=%zu)",
		tag.c_str(), what, pinged, pooled, lines.size());
}

// The ping drops the connection, with exactly one log line and that one matching `line_re`.
static void expectDropped(MockCase& f, const std::string& tag, const char* what, const std::string& line_re) {
	const bool pinged = waitQueries(f, 2, 5);
	const int left = poolConnsWithin(f.admin, 0, 5, MOCK_HG);
	usleep(500000);  // the log is written asynchronously
	const auto lines = logLinesSince(PING_LINES);
	const auto matching = logLinesSince(line_re);
	for (const auto& l : lines) diag("%s", l.c_str());
	ok(pinged && left == 0 && lines.size() == 1 && matching.size() == 1,
		"%s: %s drops the connection with one log line (pinged=%d left=%d lines=%zu matching=%zu)",
		tag.c_str(), what, pinged, left, lines.size(), matching.size());
}

static void phaseEdgeCases(MockCase& f, const std::string& tag, const std::string& saved_ping_timeout) {
	const std::string me = f.host + ":" + std::to_string(f.mock.port());

	// E1: 300 ms is far slower than a real reply, but inside a 1 s timeout.
	setVar(f.admin, "pgsql-ping_timeout_server", "1000");
	if (startCase(f, { step_expect_query(), step_sleep(300), step_send(reply_ok()) }))
		expectKept(f, tag, "a reply 300 ms late with a 1000 ms timeout", 300);
	else ok(false, "%s: E1 setup failed", tag.c_str());
	endCase(f);

	// E2: the same reply after the timeout is lowered at runtime.
	setVar(f.admin, "pgsql-ping_timeout_server", "100");
	if (startCase(f, { step_expect_query(), step_sleep(300), step_send(reply_ok()) }))
		expectDropped(f, tag, "a reply 300 ms late with the timeout lowered to 100 ms",
			".*Ping timeout during ping on " + me + " .*timeout 100ms.*");
	else ok(false, "%s: E2 setup failed", tag.c_str());
	endCase(f);
	setVar(f.admin, "pgsql-ping_timeout_server", "1000");

	// E3: messages a backend may send on its own, ahead of the reply.
	if (startCase(f, { step_expect_query(),
			step_send(pgmb_parameter_status("TimeZone", "UTC") + notice("idle ping notice") + reply_ok()) }))
		expectKept(f, tag, "ParameterStatus and NoticeResponse ahead of the reply", 0);
	else ok(false, "%s: E3 setup failed", tag.c_str());
	endCase(f);

	// E4: an ordinary error in place of EmptyQueryResponse.
	if (startCase(f, { step_expect_query(), step_send(pgmb_error_response("XX000", "idle ping refused") + pgmb_ready_for_query('I')) }))
		expectDropped(f, tag, "an ErrorResponse", ".*during ping on .*idle ping refused.*");
	else ok(false, "%s: E4 setup failed", tag.c_str());
	endCase(f);

	// E5: the backend goes away the moment the ping arrives, without a FATAL.
	if (startCase(f, { step_expect_query(), step_close() }))
		expectDropped(f, tag, "a close on receiving the ping", ".*Detected a broken connection while during ping on .*");
	else ok(false, "%s: E5 setup failed", tag.c_str());
	endCase(f);

	// E6: the reply arrives one byte at a time.
	if (startCase(f, { step_expect_query(), step_send(reply_ok(), 1, 10000) }))
		expectKept(f, tag, "a reply split into single bytes", 100);
	else ok(false, "%s: E6 setup failed", tag.c_str());
	endCase(f);

	// E7: a pooled connection the backend says is inside a transaction must not be reused.
	if (startCase(f, { step_expect_query(), step_send(reply_ok('T')) })) {
		const bool pinged = waitQueries(f, 2, 5);
		const int left = poolConnsWithin(f.admin, 0, 5, MOCK_HG);
		const auto lines = logLinesSince(PING_LINES);
		ok(pinged && left == 0 && lines.empty(),
			"%s: a reply saying a transaction is open keeps the connection out of the pool (pinged=%d left=%d logged=%zu)",
			tag.c_str(), pinged, left, lines.size());
	} else {
		ok(false, "%s: E7 setup failed", tag.c_str());
	}
	endCase(f);

	// E8: the interval is honoured as it changes. Every ping is answered, so the mock's
	// query count is the pings plus the client's query.
	{
		std::vector<Step> pings;
		for (int i = 0; i < 40; i++) { pings.push_back(step_expect_query()); pings.push_back(step_send(reply_ok())); }
		bool good = startCase(f, pings);
		sleep(3);
		const int at_1s = f.mock.queries_observed() - 1;
		good = good && setVar(f.admin, "pgsql-ping_interval_server_msec", "60000");
		usleep(1500000);  // let a round already started finish
		const int frozen_from = f.mock.queries_observed();
		sleep(4);
		const int frozen_to = f.mock.queries_observed();
		good = good && setVar(f.admin, "pgsql-ping_interval_server_msec", "1000");
		sleep(3);
		const int resumed = f.mock.queries_observed();
		const int pooled = poolConns(f.admin, MOCK_HG);
		ok(good && at_1s >= 1 && frozen_to == frozen_from && resumed > frozen_to && pooled == 1,
			"%s: pings follow the interval as it changes (1 s: %d pings; 60 s: %d -> %d; back to 1 s: %d; pooled=%d)",
			tag.c_str(), at_1s, frozen_from, frozen_to, resumed, pooled);
		endCase(f);
	}

	// E9: the server leaves the configuration while its connection is out being pinged.
	if (startCase(f, { step_expect_query(), step_sleep(800), step_send(reply_ok()) })) {
		const bool pinged = waitQueries(f, 2, 5);
		const bool removed = registerMock(f.admin, f.host, f.mock.port(), false);
		const int left = poolConnsWithin(f.admin, 0, 5, MOCK_HG);
		const bool alive = scalar(f.admin, "SELECT 1") == "1";
		const auto lines = logLinesSince(PING_LINES);
		for (const auto& l : lines) diag("%s", l.c_str());
		ok(pinged && removed && left == 0 && alive,
			"%s: a server removed mid-ping ends with its connection destroyed (pinged=%d left=%d alive=%d logged=%zu)",
			tag.c_str(), pinged, left, alive, lines.size());
	} else {
		ok(false, "%s: E9 setup failed", tag.c_str());
	}
	endCase(f);

	setVar(f.admin, "pgsql-ping_timeout_server", saved_ping_timeout.empty() ? "200" : saved_ping_timeout);
}

int main(int, char**) {
	if (cl.getEnv()) return exit_status();

	PGConnPtr admin = openAdmin();
	if (PQstatus(admin.get()) != CONNECTION_OK) { BAIL_OUT("admin connect failed"); return exit_status(); }
	PGConnPtr be = openBackend();
	if (PQstatus(be.get()) != CONNECTION_OK) { BAIL_OUT("direct backend connect failed: %s", PQerrorMessage(be.get())); return exit_status(); }

	const bool native_supported = pgsql_native_supported(admin.get());
	const int modes = native_supported ? 2 : 1;
	// Per mode: plaintext A(2) + B(3) + C + D + E(9), TLS A(3) + B(3).
	plan(modes * (2 + 3 + 1 + 1 + 9 + 3 + 3));

	const std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}

	const std::string saved_interval = runtimeVar(admin.get(), "pgsql-ping_interval_server_msec");
	const std::string saved_pct = runtimeVar(admin.get(), "pgsql-free_connections_pct");
	const std::string saved_poll = runtimeVar(admin.get(), "pgsql-poll_timeout");
	const std::string saved_ping_timeout = runtimeVar(admin.get(), "pgsql-ping_timeout_server");
	const std::string saved_monitor = runtimeVar(admin.get(), "pgsql-monitor_enabled");
	const std::string saved_native = native_supported ? runtimeVar(admin.get(), "pgsql-use_native_backend_protocol") : "";
	const std::string saved_ssl = scalar(admin.get(), "SELECT use_ssl FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(HG) + " LIMIT 1");

	// idle_session_timeout exists from PostgreSQL 14 on; phase C is skipped below that.
	const bool has_idle_timeout = atoi(scalar(be.get(), "SHOW server_version_num").c_str()) >= 140000;

	cleanupUsers(admin.get(), be.get());  // rows or roles left by an aborted run
	if (!createUser(admin.get(), be.get(), USER, nullptr)
		|| (has_idle_timeout && !createUser(admin.get(), be.get(), KA_USER, "idle_session_timeout = '4s'"))) {
		cleanupUsers(admin.get(), be.get());
		BAIL_OUT("could not create the test roles");
		return exit_status();
	}

	PgSQL_Mock_Backend mock;
	if (!mock.start()) { BAIL_OUT("mock backend failed to listen"); return exit_status(); }
	const std::string mock_host = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
	if (mock_host.empty()) { BAIL_OUT("could not find this container's IP toward ProxySQL"); return exit_status(); }
	if (!addProxyUser(admin.get(), MOCK_USER, MOCK_HG)) {
		BAIL_OUT("could not add the mock's proxy user");
		return exit_status();
	}
	// An idle worker only checks whether a ping round is due when its poll() wakes up, so
	// pings come no faster than pgsql-poll_timeout. Pin it below the 1 s ping interval.
	if (!setVar(admin.get(), "pgsql-ping_interval_server_msec", "1000") || !setVar(admin.get(), "pgsql-free_connections_pct", "100")
		|| !setVar(admin.get(), "pgsql-poll_timeout", "500") || !setVar(admin.get(), "pgsql-monitor_enabled", "false")) {
		BAIL_OUT("could not set the ping variables");
		return exit_status();
	}

	for (int m = 0; m < modes; m++) {
		const bool native = (m == 1);
		if (native_supported) setVar(admin.get(), "pgsql-use_native_backend_protocol", native ? "true" : "false");
		for (int tls = 0; tls <= 1; tls++) {
			execOk(admin.get(), "UPDATE pgsql_servers SET use_ssl=" + std::to_string(tls) + " WHERE hostgroup_id=" + std::to_string(HG));
			execOk(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");
			const char* mode = native ? "native" : "libpq";
			const std::string tag = std::string(mode) + (tls ? "/tls" : "/plain");
			phasePingsReachServer(admin.get(), be.get(), tag, tls, mode);
			phaseKilledWhileIdle(admin.get(), be.get(), tag);
			if (!tls) {
				if (has_idle_timeout) phaseKeptAlive(admin.get(), be.get(), tag);
				else skip(1, "%s: idle_session_timeout needs PostgreSQL 14+", tag.c_str());
				phaseSilentBackend(admin.get(), mock, mock_host, tag, mode);
				MockCase mc { admin.get(), mock, mock_host, mode };
				phaseEdgeCases(mc, tag, saved_ping_timeout);
			}
		}
	}

	flushPool(admin.get());
	execOk(admin.get(), "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(MOCK_HG));
	cleanupUsers(admin.get(), be.get());
	execOk(admin.get(), "UPDATE pgsql_servers SET use_ssl=" + (saved_ssl.empty() ? std::string("0") : saved_ssl) + " WHERE hostgroup_id=" + std::to_string(HG));
	execOk(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME");
	setVar(admin.get(), "pgsql-ping_interval_server_msec", saved_interval.empty() ? "10000" : saved_interval);
	setVar(admin.get(), "pgsql-free_connections_pct", saved_pct.empty() ? "10" : saved_pct);
	setVar(admin.get(), "pgsql-poll_timeout", saved_poll.empty() ? "2000" : saved_poll);
	if (!saved_monitor.empty()) setVar(admin.get(), "pgsql-monitor_enabled", saved_monitor);
	if (native_supported && !saved_native.empty()) setVar(admin.get(), "pgsql-use_native_backend_protocol", saved_native);
	flushPool(admin.get());

	return exit_status();
}
