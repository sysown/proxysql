/**
 * @file pgsql-native_notify-t.cpp
 * @brief A notification raised by one client must not reach another, and must not
 *        kill anyone's session.
 *
 * PostgreSQL sends NotificationResponse ('A') on its own initiative, to every
 * connection that ran LISTEN, whether or not a query is in flight. ProxySQL hands
 * backend connections around between clients, so such a message belongs to a
 * client that may no longer be holding the connection it arrives on.
 *
 * Scenario A -- the connection is pinned to a session:
 *   native: LISTEN is supported. The subscription pins the connection, and the
 *           notification reaches the subscriber while it sits idle on the socket,
 *           which is the entire point of the feature.
 *   libpq:  LISTEN is refused, so the only way to subscribe is the multi-statement
 *           gap, which leaves no status flag. An unflagged connection is still read
 *           as a dead backend and the client session is destroyed. Asserted as
 *           broken, so the fix cannot land unnoticed.
 *
 * Scenario B -- the connection goes back to the pool:
 *   no client that did not subscribe may see the notification, on either path, and
 *   it must not be stored in the query cache and replayed for the whole TTL.
 *
 * The second half of the file is the lifecycle of the pin that makes scenario A
 * work: when it is taken, when it is released, and what becomes of the pinned
 * connection when the client disappears, when the backend is killed under it, and
 * when the link is encrypted, plus COPY, eight concurrent subscribers and a second
 * hostgroup served by another server. Backend facts -- whether a connection kept its subscription, whether
 * it is really encrypted -- are read from PostgreSQL over a direct connection,
 * never from ProxySQL, which is the component under test.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <cstring>
#include <ctime>
#include <signal.h>
#include <unistd.h>
#include <sys/select.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static std::fstream f_proxysql_log{};
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host
	   << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username
	   << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execSQL(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(res);
	return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
	std::string out;
	PGresult* res = PQexec(c, q.c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		out = PQgetvalue(res, 0, 0);
	PQclear(res);
	return out;
}

static bool setVar(PGconn* admin, const std::string& name, const std::string& value) {
	return execSQL(admin, "SET " + name + "='" + value + "'") &&
	       execSQL(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

struct ServerRow { std::string hostname, port, max_connections, use_ssl, comment; };

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin,
	    ("SELECT hostname, port, max_connections, use_ssl, comment FROM pgsql_servers "
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

// Backend connections keep the protocol they were opened with, so flipping
// pgsql-use_native_backend_protocol does nothing to connections already in the
// pool. Without this a "native" phase silently re-runs the libpq one.
// max_conns_override caps the pool so connection reuse between phases is
// predictable; empty keeps whatever the row had.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved,
                             const std::string& max_conns_override = "",
                             const std::string& use_ssl_override = "") {
	if (saved.empty()) return false;
	if (!execSQL(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		std::string mc = max_conns_override.empty()
			? (r.max_connections.empty() ? std::string("1000") : r.max_connections)
			: max_conns_override;
		const std::string ssl = use_ssl_override.empty() ? r.use_ssl : use_ssl_override;
		std::string ins = "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) VALUES ("
			+ std::to_string(hg) + ",'" + r.hostname + "'," + r.port + "," + mc + "," + ssl
			+ ",'" + r.comment + "')";
		if (!execSQL(admin, ins)) return false;
	}
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(300000);
	return true;
}

static void drainLogToNow() {
	get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

// ProxySQL writes its log asynchronously to the SQL that triggers it, so a single scan
// right after the query is racy; this polls, and rewinds the stream when nothing matched.
static const char* BROKEN_IDLE_RE = ".*Detected broken idle connection.*";
static bool sawBrokenIdleWarning() {
	return wait_for_log_match(f_proxysql_log, BROKEN_IDLE_RE, 2000, 100);
}

static uint64_t now_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

// Straight to PostgreSQL: the only trustworthy source for whether a backend still exists
// and whether a link is really encrypted.
static PGConnPtr open_backend_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port
	   << " user=" << cl.pgsql_server_username << " password=" << cl.pgsql_server_password
	   << " dbname=postgres";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// Connections held by sessions right now, over every hostgroup. This is the pin, seen
// from outside.
static long connUsed(PGconn* admin) {
	const std::string v = scalar(admin, "SELECT SUM(ConnUsed) FROM stats_pgsql_connection_pool");
	return v.empty() ? -1 : atol(v.c_str());
}

// Pool returns are not synchronous with the query that freed the connection, so a single
// read is racy. Returns the last value seen, so a failing assertion can print it.
static long waitConnUsed(PGconn* admin, long expected, int timeout_ms) {
	const uint64_t deadline = now_ms() + timeout_ms;
	long v = connUsed(admin);
	while (v != expected && now_ms() < deadline) {
		usleep(100000);
		v = connUsed(admin);
	}
	return v;
}

// A query that cannot hang the run: losing buffered bytes wedges the client rather than
// failing it, so "no answer" has to be a bounded outcome, not a blocked PQexec.
enum QRes { Q_OK, Q_FAILED, Q_TIMEOUT };

static QRes query_with_deadline(PGconn* c, const char* sql, int timeout_ms, std::string* val = NULL) {
	if (PQsendQuery(c, sql) == 0) return Q_FAILED;
	const uint64_t deadline = now_ms() + timeout_ms;
	for (;;) {
		if (PQconsumeInput(c) == 0) return Q_FAILED;
		if (!PQisBusy(c)) break;
		if (now_ms() >= deadline) return Q_TIMEOUT;
		int sock = PQsocket(c);
		if (sock < 0) return Q_FAILED;
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		struct timeval tv = { 0, 100 * 1000 };
		if (select(sock + 1, &rfds, NULL, NULL, &tv) < 0) return Q_FAILED;
	}
	QRes out = Q_FAILED;
	PGresult* res;
	while ((res = PQgetResult(c)) != NULL) {
		const ExecStatusType st = PQresultStatus(res);
		out = (st == PGRES_TUPLES_OK || st == PGRES_COMMAND_OK) ? Q_OK : Q_FAILED;
		if (val && st == PGRES_TUPLES_OK && PQntuples(res) > 0) *val = PQgetvalue(res, 0, 0);
		PQclear(res);
	}
	return out;
}

static const char* qres_name(QRes r) {
	return r == Q_OK ? "answered" : (r == Q_TIMEOUT ? "NO ANSWER (wedged)" : "failed");
}

// pg_backend_pid() through the proxy is intercepted and answered locally, so the backend
// is identified by the statement text PostgreSQL remembers for it instead.
static int backendPidForChannel(PGconn* be, const std::string& channel) {
	const std::string v = scalar(be,
	    "SELECT pid FROM pg_stat_activity WHERE backend_type='client backend'"
	    " AND pid <> pg_backend_pid() AND query LIKE '%" + channel + "%' LIMIT 1");
	return v.empty() ? -1 : atoi(v.c_str());
}

static std::string chan(const char* tag) {
	return std::string("ll_") + tag + "_" + std::to_string(getpid());
}

struct Notification { std::string channel, payload; };

// Collect whatever the server pushed, without sending a query -- PQconsumeInput
// only reads, so this is the idle path a LISTEN client actually sits in.
static std::vector<Notification> drain_notifications(PGconn* c, int timeout_ms) {
	std::vector<Notification> out;
	int waited = 0;
	while (waited < timeout_ms) {
		PGnotify* n = PQnotifies(c);
		if (n) {
			out.push_back({ n->relname ? n->relname : "", n->extra ? n->extra : "" });
			PQfreemem(n);
			waited = 0;
			continue;
		}
		int sock = PQsocket(c);
		if (sock < 0) break;
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		struct timeval tv = { 0, 50 * 1000 };
		int r = select(sock + 1, &rfds, NULL, NULL, &tv);
		if (r > 0) {
			if (PQconsumeInput(c) == 0) break;
		} else {
			waited += 50;
		}
	}
	return out;
}

static std::string uniqueChannel(const char* tag, bool native) {
	return std::string("nn_") + tag + (native ? "_nat_" : "_pq_") + std::to_string(getpid());
}

// Registers a listener on whatever backend connection this session is using.
static bool subscribe(PGconn* c, const std::string& channel) {
	std::string q = "SELECT 1; LISTEN " + channel;
	PGresult* r = PQexec(c, q.c_str());
	bool ok_ = (PQresultStatus(r) == PGRES_TUPLES_OK || PQresultStatus(r) == PGRES_COMMAND_OK);
	if (!ok_) diag("subscribe failed: %s", PQerrorMessage(c));
	PQclear(r);
	return ok_;
}

static bool notifyChannel(PGconn* c, const std::string& channel, const std::string& payload) {
	std::string q = "NOTIFY " + channel + ", '" + payload + "'";
	PGresult* r = PQexec(c, q.c_str());
	bool ok_ = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	return ok_;
}

// ---------------------------------------------------------------------------
// Scenario A: the notification lands on a connection pinned to an idle session.
// native: LISTEN is supported, the connection is pinned by it, and the notification
//         reaches the client that subscribed, with no query in flight.
// libpq:  LISTEN is refused, so the only way to subscribe is the multi-statement gap,
//         which leaves no status flag -- and an unflagged connection still gets read
//         as a dead backend. Pinned as a known open issue.
// ---------------------------------------------------------------------------
static void scenario_pinned_session(PGconn* admin, bool native,
                                    const std::vector<ServerRow>& saved) {
	const std::string mode = native ? "native" : "libpq";
	if (!setVar(admin, "pgsql-multiplexing", "false") ||
	    !setVar(admin, "pgsql-use_native_backend_protocol", native ? "true" : "false") ||
	    !flushBackendPool(admin, BACKEND_HG, saved, "10")) {
		ok(false, "[%s] scenario A setup failed", mode.c_str());
		ok(false, "[%s] scenario A setup failed", mode.c_str());
		return;
	}
	const std::string channel = uniqueChannel("pin", native);

	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !notifier || PQstatus(notifier.get()) != CONNECTION_OK) {
		ok(false, "[%s] scenario A could not open client connections", mode.c_str());
		ok(false, "[%s] scenario A could not open client connections", mode.c_str());
		return;
	}

	bool subscribed;
	if (native) {
		// Supported now, and this is what sets the status flag that pins the connection.
		PGresult* r = PQexec(listener.get(), ("LISTEN " + channel).c_str());
		subscribed = (PQresultStatus(r) == PGRES_COMMAND_OK);
		PQclear(r);
	} else {
		subscribed = subscribe(listener.get(), channel);   // multi-statement gap, no flag
	}
	if (!subscribed) {
		ok(false, "[%s] scenario A could not register a listener", mode.c_str());
		ok(false, "[%s] scenario A could not register a listener", mode.c_str());
		return;
	}

	// Read the log from here: flushing the pool tears down every pooled connection and
	// logs the same warning for each, which would swamp the one line this is about.
	drainLogToNow();
	// Multiplexing is off, so the notifier holds a different backend connection and the
	// notification reaches the listener's connection while that session is idle.
	notifyChannel(notifier.get(), channel, "pinned");

	if (native) {
		// The point of the feature: it arrives with no query in flight.
		std::vector<Notification> got = drain_notifications(listener.get(), 3000);
		ok(got.size() == 1 && got[0].channel == channel && got[0].payload == "pinned",
		   "[native] the subscriber receives the notification while idle (got %zu)", got.size());
		PGresult* r = PQexec(listener.get(), "SELECT 42");
		const bool alive = (PQresultStatus(r) == PGRES_TUPLES_OK) &&
		                   (std::string(PQgetvalue(r, 0, 0)) == "42") &&
		                   (PQstatus(listener.get()) == CONNECTION_OK);
		PQclear(r);
		ok(alive, "[native] the session is still usable afterwards");
	} else {
		usleep(1500000);
		PGresult* r = PQexec(listener.get(), "SELECT 42");
		const bool alive = (PQresultStatus(r) == PGRES_TUPLES_OK) &&
		                   (PQstatus(listener.get()) == CONNECTION_OK);
		PQclear(r);
		ok(!alive, "[libpq] session is still killed by an idle notification (known open issue)");
		ok(sawBrokenIdleWarning(),
		   "[libpq] 'Detected broken idle connection' still logged (known open issue)");
	}
}

// ---------------------------------------------------------------------------
// Scenario B: the notification lands on a connection that goes back to the pool.
// ---------------------------------------------------------------------------
static void scenario_pooled_conn_leaks_nothing(PGconn* admin, bool native,
                                               const std::vector<ServerRow>& saved,
                                               bool with_cache) {
	const std::string mode = native ? "native" : "libpq";
	const char* what = with_cache ? "cached" : "uncached";
	if (!setVar(admin, "pgsql-multiplexing", "true") ||
	    !setVar(admin, "pgsql-use_native_backend_protocol", native ? "true" : "false") ||
	    !flushBackendPool(admin, BACKEND_HG, saved, "1")) {
		ok(false, "[%s/%s] scenario B setup failed", mode.c_str(), what);
		return;
	}
	const std::string channel = uniqueChannel(with_cache ? "poolc" : "pool", native);
	const std::string probe = "SELECT 'v' AS nn_probe";

	if (with_cache) {
		// match_digest sees the normalized digest, so the literal is already a '?';
		// matching on the alias is what actually fires.
		execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8801");
		execSQL(admin, "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl,apply)"
		                 " VALUES (8801,1,'AS nn_probe',10000,1)");
		execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
		execSQL(admin, "PROXYSQL FLUSH QUERY CACHE");
	}
	const long hits_before = with_cache
		? atol(scalar(admin, "SELECT variable_value FROM stats_pgsql_global"
		                          " WHERE variable_name='Query_Cache_count_GET_OK'").c_str())
		: 0;

	{
		PGConnPtr listener = open_client_conn();
		if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
		    !subscribe(listener.get(), channel)) {
			ok(false, "[%s/%s] scenario B could not register a listener", mode.c_str(), what);
			if (with_cache) execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8801");
			return;
		}
	}   // listener disconnects; the subscribed connection goes back to the pool

	PGConnPtr notifier = open_client_conn();
	if (!notifier || PQstatus(notifier.get()) != CONNECTION_OK) {
		ok(false, "[%s/%s] scenario B could not open the notifier", mode.c_str(), what);
		if (with_cache) execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8801");
		return;
	}
	notifyChannel(notifier.get(), channel, "SHOULD-NOT-LEAK");
	usleep(500000);

	// Whether the notification arrived inside the notifier's own cycle or is sitting
	// on the pooled connection, no client that never subscribed may see it.
	size_t leaked = 0;
	int probes_ok = 0;
	for (int i = 0; i < 3; i++) {
		PGConnPtr v = open_client_conn();
		if (!v || PQstatus(v.get()) != CONNECTION_OK) continue;
		for (int j = 0; j < 2; j++) {
			PGresult* r = PQexec(v.get(), probe.c_str());
			if (PQresultStatus(r) == PGRES_TUPLES_OK && std::string(PQgetvalue(r, 0, 0)) == "v") probes_ok++;
			PQclear(r);
		}
		leaked += drain_notifications(v.get(), 200).size();
	}
	leaked += drain_notifications(notifier.get(), 200).size();

	ok(leaked == 0 && probes_ok == 6,
	   "[%s/%s] no notification reaches a client that never subscribed (leaked=%zu, good probes=%d/6)",
	   mode.c_str(), what, leaked, probes_ok);

	if (with_cache) {
		const long hits_after = atol(scalar(admin, "SELECT variable_value FROM stats_pgsql_global"
		                                                " WHERE variable_name='Query_Cache_count_GET_OK'").c_str());
		// Without a hit, "no notification" would prove nothing -- the cache would simply
		// not have been in the picture.
		ok(hits_after > hits_before,
		   "[%s/cached] the query cache actually served the probe (hits +%ld)",
		   mode.c_str(), hits_after - hits_before);
		execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8801");
		execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	}
}

// ===========================================================================
// Lifecycle of the pin. Everything below is native only.
//
// A subscription lives on the backend connection, so ProxySQL stops multiplexing
// it: the connection stays with the session that ran LISTEN. That pin is visible
// from outside as stats_pgsql_connection_pool.ConnUsed -- an idle session that
// still holds its connection counts 1, one that handed it back counts 0.
// ===========================================================================

// Taking and releasing the pin. UNLISTEN <channel> deliberately does not release it:
// channels are not tracked, so unpinning while a subscription remains would hand the
// next notification to whichever client picks the connection up.
static void scenario_pin_lifecycle(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		for (int i = 0; i < 6; i++) ok(false, "pin lifecycle setup failed");
		return;
	}
	PGConnPtr c = open_client_conn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		for (int i = 0; i < 6; i++) ok(false, "pin lifecycle could not connect");
		return;
	}

	execSQL(c.get(), "SELECT 1");
	long v = waitConnUsed(admin, 0, 5000);
	ok(v == 0, "an unsubscribed session hands its backend connection back when it goes idle (ConnUsed=%ld)", v);

	const std::string a = chan("pinA"), b = chan("pinB");
	execSQL(c.get(), "LISTEN " + a);
	v = waitConnUsed(admin, 1, 5000);
	ok(v == 1, "LISTEN keeps the connection with the session that subscribed (ConnUsed=%ld)", v);

	execSQL(c.get(), "UNLISTEN " + a);
	v = waitConnUsed(admin, 1, 2000);
	ok(v == 1, "UNLISTEN <channel> deliberately does not release the pin, since ProxySQL does not"
	           " track channels (ConnUsed=%ld)", v);

	execSQL(c.get(), "UNLISTEN *");
	v = waitConnUsed(admin, 0, 5000);
	ok(v == 0, "UNLISTEN * releases the pin (ConnUsed=%ld)", v);

	execSQL(c.get(), "LISTEN " + b);
	waitConnUsed(admin, 1, 5000);
	execSQL(c.get(), "DISCARD ALL");
	v = waitConnUsed(admin, 0, 5000);
	ok(v == 0, "DISCARD ALL releases the pin (ConnUsed=%ld)", v);

	// The star may abut the keyword, and the digest keeps it joined, so a release that
	// expects a space leaves the connection pinned for the rest of the client's life.
	const std::string d = chan("pinC");
	execSQL(c.get(), "LISTEN " + d);
	waitConnUsed(admin, 1, 5000);
	execSQL(c.get(), "UNLISTEN*");
	v = waitConnUsed(admin, 0, 5000);
	ok(v == 0, "UNLISTEN* with no space releases the pin too (ConnUsed=%ld)", v);
}

// A notification that landed while the session was idle leaves bytes buffered when the
// next query starts. Clearing them there truncates the message and the client waits
// forever for an answer parsed out of step. Large payloads arrive split across reads.
static void scenario_buffered_between_queries(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "buffered-notification setup failed");
		ok(false, "buffered-notification setup failed");
		return;
	}
	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !notifier || PQstatus(notifier.get()) != CONNECTION_OK) {
		ok(false, "buffered-notification could not connect");
		ok(false, "buffered-notification could not connect");
		return;
	}
	const std::string ch = chan("buf");
	execSQL(listener.get(), "LISTEN " + ch);

	// Separate statements, and distinct payloads: PostgreSQL folds identical
	// notifications raised inside one transaction into a single delivery.
	const int N_NOTIF = 5;
	const std::string bulk(7900, 'x');
	std::vector<std::string> sent;
	for (int i = 0; i < N_NOTIF; i++) {
		const std::string p = bulk + std::to_string(i);
		sent.push_back(p);
		notifyChannel(notifier.get(), ch, p);
	}
	usleep(500000);   // let them reach the listener's connection while it is idle

	// Issued without draining first, so the bytes are still buffered when it starts.
	std::string val;
	const QRes rc = query_with_deadline(listener.get(), "SELECT 42", 5000, &val);
	ok(rc == Q_OK && val == "42",
	   "a query issued while notifications sit buffered still gets its answer (%s)", qres_name(rc));

	std::vector<Notification> got = drain_notifications(listener.get(), 3000);
	int intact = 0;
	for (const auto& n : got) {
		for (const auto& s : sent) if (n.channel == ch && n.payload == s) { intact++; break; }
	}
	ok(intact == N_NOTIF, "all %d large notifications survive intact (%d of %zu received)",
	   N_NOTIF, intact, got.size());
}

// The connection is not closed when the subscriber leaves: it is reset, which clears the
// subscription, and pooled. The pid comparison is what makes this mean anything, since a
// brand new connection would also report no channels. max_connections stays uncapped --
// capping it to 1 makes the next client race the reset and get a fresh backend.
static void scenario_client_disconnect(PGconn* admin, PGconn* be, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		for (int i = 0; i < 4; i++) ok(false, "disconnect setup failed");
		return;
	}
	const std::string ch = chan("disc");
	int pid_before = -1;
	{
		PGConnPtr listener = open_client_conn();
		if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
		    !execSQL(listener.get(), "LISTEN " + ch)) {
			for (int i = 0; i < 4; i++) ok(false, "disconnect scenario could not subscribe");
			return;
		}
		waitConnUsed(admin, 1, 5000);
		pid_before = backendPidForChannel(be, ch);
	}   // the subscriber goes away with its connection still pinned

	// Wait for the reset to finish and the connection to land back in the pool, so the
	// next client finds it there instead of opening its own.
	waitConnUsed(admin, 0, 5000);
	const uint64_t deadline = now_ms() + 5000;
	std::string freed = scalar(admin, "SELECT SUM(ConnFree) FROM stats_pgsql_connection_pool");
	while ((freed.empty() || atol(freed.c_str()) < 1) && now_ms() < deadline) {
		usleep(100000);
		freed = scalar(admin, "SELECT SUM(ConnFree) FROM stats_pgsql_connection_pool");
	}

	PGConnPtr next = open_client_conn();
	if (!next || PQstatus(next.get()) != CONNECTION_OK) {
		for (int i = 0; i < 4; i++) ok(false, "disconnect scenario could not open the next client");
		return;
	}
	const std::string marker = "ll_reuse_" + std::to_string(getpid());
	execSQL(next.get(), "SELECT 1 AS " + marker);
	const int pid_after = backendPidForChannel(be, marker);
	ok(pid_before > 0 && pid_after == pid_before,
	   "the next client is handed the very same backend connection (pid %d -> %d, %s free in the pool)",
	   pid_before, pid_after, freed.empty() ? "0" : freed.c_str());

	const std::string channels = scalar(next.get(),
	    "SELECT coalesce(string_agg(c,','),'(none)') FROM pg_listening_channels() c");
	ok(channels == "(none)",
	   "and that recycled connection carries no subscription into it (channels=%s)", channels.c_str());

	// A subscription that is gone but a pin that is not would hold this connection out
	// of the pool for as long as the client lives.
	const long v = waitConnUsed(admin, 0, 5000);
	ok(v == 0, "and it is no longer pinned to the client that inherited it (ConnUsed=%ld)", v);

	PGConnPtr notifier = open_client_conn();
	PGConnPtr probe = open_client_conn();
	if (!notifier || PQstatus(notifier.get()) != CONNECTION_OK ||
	    !probe || PQstatus(probe.get()) != CONNECTION_OK) {
		ok(false, "disconnect scenario could not open follow-up connections");
		return;
	}
	notifyChannel(notifier.get(), ch, "after-disconnect");
	usleep(500000);
	std::string val;
	const QRes rc = query_with_deadline(probe.get(), "SELECT 42", 5000, &val);
	const size_t leaked = drain_notifications(probe.get(), 300).size()
	                    + drain_notifications(next.get(), 300).size()
	                    + drain_notifications(notifier.get(), 300).size();
	ok(leaked == 0 && rc == Q_OK && val == "42",
	   "no later client receives the dead subscriber's notification (leaked=%zu, probe %s)",
	   leaked, qres_name(rc));
}

// PostgreSQL speaking first with an error instead of a notification. The proxy has to
// end that session and stay up, not hang it.
static void scenario_backend_killed(PGconn* admin, PGconn* be, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "backend-kill setup failed");
		ok(false, "backend-kill setup failed");
		return;
	}
	const std::string ch = chan("kill");
	PGConnPtr listener = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !execSQL(listener.get(), "LISTEN " + ch)) {
		ok(false, "backend-kill scenario could not subscribe");
		ok(false, "backend-kill scenario could not subscribe");
		return;
	}
	waitConnUsed(admin, 1, 5000);

	const int pid = backendPidForChannel(be, ch);
	const bool killed = (pid > 0) && !scalar(be, "SELECT pg_terminate_backend(" + std::to_string(pid) + ")").empty();
	diag("victim backend pid=%d killed=%s", pid, killed ? "yes" : "no");
	usleep(1000000);

	// Either answer is acceptable as long as it is an answer: the client may be
	// dropped, or told the connection died. Silence is the failure.
	std::string val;
	const QRes rc = query_with_deadline(listener.get(), "SELECT 42", 5000, &val);
	ok(killed && rc != Q_TIMEOUT,
	   "a session whose pinned backend was terminated is not left hanging (kill=%s, query %s)",
	   killed ? "yes" : "no", qres_name(rc));

	PGConnPtr fresh = open_client_conn();
	std::string v2;
	const QRes rc2 = (fresh && PQstatus(fresh.get()) == CONNECTION_OK)
		? query_with_deadline(fresh.get(), "SELECT 42", 5000, &v2) : Q_FAILED;
	ok(rc2 == Q_OK && v2 == "42",
	   "the proxy keeps serving after a backend died under a pinned connection (%s)", qres_name(rc2));
}

// The same delivery over an encrypted backend link.
static void scenario_tls_backend(PGconn* admin, PGconn* be, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved, "", "1")) {
		ok(false, "TLS setup failed");
		ok(false, "TLS setup failed");
		return;
	}
	const std::string ch = chan("tls");
	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	const bool up = listener && PQstatus(listener.get()) == CONNECTION_OK &&
	                notifier && PQstatus(notifier.get()) == CONNECTION_OK &&
	                execSQL(listener.get(), "LISTEN " + ch);
	if (!up) {
		ok(false, "TLS scenario could not subscribe");
		ok(false, "TLS scenario could not subscribe");
		flushBackendPool(admin, BACKEND_HG, saved, "", "0");
		return;
	}
	waitConnUsed(admin, 1, 5000);

	// Without this the whole scenario passes on a plaintext connection and proves
	// nothing about TLS. PostgreSQL is asked, not ProxySQL.
	const int pid = backendPidForChannel(be, ch);
	const std::string ssl = (pid > 0)
		? scalar(be, "SELECT ssl::text FROM pg_stat_ssl WHERE pid=" + std::to_string(pid)) : "";
	ok(ssl == "true" || ssl == "t",
	   "the pinned backend connection is really encrypted (pid=%d, pg_stat_ssl.ssl='%s')", pid, ssl.c_str());

	notifyChannel(notifier.get(), ch, "over-tls");
	std::vector<Notification> got = drain_notifications(listener.get(), 3000);
	ok(got.size() == 1 && got[0].channel == ch && got[0].payload == "over-tls",
	   "the notification is relayed over the TLS backend connection (got %zu)", got.size());

	listener.reset();
	notifier.reset();
	flushBackendPool(admin, BACKEND_HG, saved, "", "0");
}

// Eight subscribers at once: each pins its own connection, and each notification must
// reach its own subscriber and no other.
static void scenario_many_listeners(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "many-listeners setup failed");
		ok(false, "many-listeners setup failed");
		return;
	}
	const int N_SUB = 8;
	std::vector<PGConnPtr> listeners;
	std::vector<std::string> channels;
	for (int i = 0; i < N_SUB; i++) {
		PGConnPtr c = open_client_conn();
		const std::string ch = chan(("m" + std::to_string(i)).c_str());
		if (!c || PQstatus(c.get()) != CONNECTION_OK || !execSQL(c.get(), "LISTEN " + ch)) {
			ok(false, "many-listeners could not subscribe listener %d", i);
			ok(false, "many-listeners could not subscribe listener %d", i);
			return;
		}
		listeners.push_back(std::move(c));
		channels.push_back(ch);
	}
	const long used = waitConnUsed(admin, N_SUB, 5000);

	PGConnPtr notifier = open_client_conn();
	if (!notifier || PQstatus(notifier.get()) != CONNECTION_OK) {
		ok(false, "many-listeners could not open the notifier");
		ok(false, "many-listeners could not open the notifier");
		return;
	}
	for (int i = 0; i < N_SUB; i++) notifyChannel(notifier.get(), channels[i], "m" + std::to_string(i));

	int correct = 0, wrong = 0;
	for (int i = 0; i < N_SUB; i++) {
		std::vector<Notification> got = drain_notifications(listeners[i].get(), 2000);
		for (const auto& n : got) {
			if (n.channel == channels[i] && n.payload == ("m" + std::to_string(i))) correct++;
			else wrong++;
		}
	}
	ok(correct == N_SUB && wrong == 0,
	   "each of %d subscribers receives exactly its own notification (own=%d, foreign=%d, pinned conns=%ld)",
	   N_SUB, correct, wrong, used);

	int alive = 0;
	for (int i = 0; i < N_SUB; i++) {
		std::string v;
		if (query_with_deadline(listeners[i].get(), "SELECT 42", 5000, &v) == Q_OK && v == "42") alive++;
	}
	ok(alive == N_SUB, "all %d subscriber sessions are still usable afterwards (%d alive)", N_SUB, alive);
}

// COPY takes the connection over for its own message flow; the subscription has to
// survive it.
static void scenario_copy_on_pinned(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "COPY setup failed");
		return;
	}
	const std::string ch = chan("copy");
	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !notifier || PQstatus(notifier.get()) != CONNECTION_OK ||
	    !execSQL(listener.get(), "LISTEN " + ch)) {
		ok(false, "COPY scenario could not subscribe");
		return;
	}
	waitConnUsed(admin, 1, 5000);

	bool copy_ok = false;
	PGresult* res = PQexec(listener.get(), "COPY (SELECT 1) TO STDOUT");
	if (PQresultStatus(res) == PGRES_COPY_OUT) {
		char* buf = NULL;
		int rows = 0, n;
		while ((n = PQgetCopyData(listener.get(), &buf, 0)) > 0) { rows++; PQfreemem(buf); buf = NULL; }
		PQclear(res);
		res = PQgetResult(listener.get());
		copy_ok = (n == -1) && (rows == 1) && res && PQresultStatus(res) == PGRES_COMMAND_OK;
	}
	if (res) PQclear(res);

	notifyChannel(notifier.get(), ch, "after-copy");
	std::vector<Notification> got = drain_notifications(listener.get(), 3000);
	ok(copy_ok && got.size() == 1 && got[0].payload == "after-copy",
	   "COPY runs on a pinned connection and the subscription survives it (copy=%s, notifications=%zu)",
	   copy_ok ? "ok" : "failed", got.size());
}

// "SELECT 1; LISTEN chan" registers a real subscription, but status flags are read from
// the first keyword of the digest, so it is not tracked and the connection is not pinned.
// Deliberate, and shared with CREATE TEMP TABLE, PREPARE, SET and LOCK TABLE written the
// same way. Asserted so the behaviour cannot drift unnoticed.
static void scenario_multi_statement_listen_not_tracked(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "multi-statement LISTEN setup failed");
		return;
	}
	const std::string ch = chan("multi");
	PGConnPtr listener = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !subscribe(listener.get(), ch)) {          // sends "SELECT 1; LISTEN <chan>"
		ok(false, "multi-statement LISTEN could not subscribe");
		return;
	}
	// Nothing else in this session pins anything, so the connection going back to the pool
	// is what "the subscription was not recorded" looks like from outside.
	const long v = waitConnUsed(admin, 0, 5000);
	ok(v == 0, "a LISTEN written behind another statement is deliberately not tracked,"
	           " so the connection is not pinned (ConnUsed=%ld)", v);
}

// PostgreSQL cannot splice a notification into a result it is already sending, so it
// arrives at the tail of that result, read by the result parser rather than the idle
// relay. The cache copies those same bytes, so caching such a result would replay the
// notification to every later client for the whole TTL. The control run is what stops
// "not cached" from merely meaning the rule never matched.
static void scenario_notification_during_query(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "in-flight notification setup failed");
		ok(false, "in-flight notification setup failed");
		return;
	}
	execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8841");
	execSQL(admin, "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,cache_ttl,apply)"
	               " VALUES (8841,1,'AS ndq_probe',10000,1)");
	execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

	const std::string ch = chan("inflight");
	const char* slow_query = "SELECT pg_sleep(2) AS ndq_probe";
	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !notifier || PQstatus(notifier.get()) != CONNECTION_OK ||
	    !execSQL(listener.get(), "LISTEN " + ch)) {
		ok(false, "in-flight scenario could not subscribe");
		ok(false, "in-flight scenario could not subscribe");
		execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8841");
		execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
		return;
	}
	waitConnUsed(admin, 1, 5000);

	// Subject first, on an empty cache, so the query really reaches the backend.
	execSQL(admin, "PROXYSQL FLUSH QUERY CACHE");
	const long sets_before = atol(scalar(admin, "SELECT variable_value FROM stats_pgsql_global"
	                                            " WHERE variable_name='Query_Cache_count_SET'").c_str());
	// Sent without blocking, so the NOTIFY below lands while this query is still running.
	const bool sent = (PQsendQuery(listener.get(), slow_query) == 1);
	notifyChannel(notifier.get(), ch, "during-query");
	std::string val;
	QRes rc = Q_FAILED;
	if (sent) {
		const uint64_t deadline = now_ms() + 10000;
		for (;;) {
			if (PQconsumeInput(listener.get()) == 0) { rc = Q_FAILED; break; }
			if (!PQisBusy(listener.get())) {
				PGresult* res;
				while ((res = PQgetResult(listener.get())) != NULL) {
					rc = (PQresultStatus(res) == PGRES_TUPLES_OK) ? Q_OK : Q_FAILED;
					PQclear(res);
				}
				break;
			}
			if (now_ms() >= deadline) { rc = Q_TIMEOUT; break; }
			int sock = PQsocket(listener.get());
			fd_set rfds;
			FD_ZERO(&rfds);
			FD_SET(sock, &rfds);
			struct timeval tv = { 0, 50 * 1000 };
			if (select(sock + 1, &rfds, NULL, NULL, &tv) < 0) { rc = Q_FAILED; break; }
		}
	}
	std::vector<Notification> got = drain_notifications(listener.get(), 2000);
	ok(rc == Q_OK && got.size() == 1 && got[0].channel == ch && got[0].payload == "during-query",
	   "a notification raised during a query on that connection is delivered with the result"
	   " (query %s, notifications=%zu)", qres_name(rc), got.size());

	const long sets_subject = atol(scalar(admin, "SELECT variable_value FROM stats_pgsql_global"
	                                             " WHERE variable_name='Query_Cache_count_SET'").c_str());
	// Control: the identical query with no notification attached must be cached, otherwise
	// the assertion above it proves nothing about the guard.
	execSQL(admin, "PROXYSQL FLUSH QUERY CACHE");
	PGConnPtr plain = open_client_conn();
	if (plain && PQstatus(plain.get()) == CONNECTION_OK) execSQL(plain.get(), slow_query);
	const long sets_control = atol(scalar(admin, "SELECT variable_value FROM stats_pgsql_global"
	                                             " WHERE variable_name='Query_Cache_count_SET'").c_str());
	ok(sets_subject == sets_before && sets_control > sets_subject,
	   "and that result is kept out of the query cache (carrying a notification +%ld,"
	   " same query without one +%ld)", sets_subject - sets_before, sets_control - sets_subject);

	listener.reset();
	notifier.reset();
	plain.reset();
	execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8841");
	execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	execSQL(admin, "PROXYSQL FLUSH QUERY CACHE");
}

// LISTEN sent as Parse/Bind/Describe/Execute/Sync rather than as a simple query. The gate
// and the pin are both meant to be protocol-agnostic, and nothing else asserted it. The
// control run is what gives it meaning: extended-protocol statements must not pin by
// themselves, or "pinned" below would say nothing about LISTEN.
static void scenario_extended_protocol_listen(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved)) {
		ok(false, "extended-protocol LISTEN setup failed");
		ok(false, "extended-protocol LISTEN setup failed");
		return;
	}
	long ctrl_held = -1;
	{	// zero parameters still uses the extended protocol
		PGConnPtr ctrl = open_client_conn();
		if (ctrl && PQstatus(ctrl.get()) == CONNECTION_OK) {
			PGresult* r = PQexecParams(ctrl.get(), "SELECT 1 AS ext_ctrl", 0, NULL, NULL, NULL, NULL, 0);
			PQclear(r);
			ctrl_held = waitConnUsed(admin, 0, 5000);
		}
	}

	const std::string ch = chan("ext");
	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !notifier || PQstatus(notifier.get()) != CONNECTION_OK) {
		ok(false, "extended-protocol LISTEN could not connect");
		ok(false, "extended-protocol LISTEN could not connect");
		return;
	}
	PGresult* r = PQexecParams(listener.get(), ("LISTEN " + ch).c_str(), 0, NULL, NULL, NULL, NULL, 0);
	const bool accepted = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	const long held = waitConnUsed(admin, 1, 5000);
	ok(accepted && held == 1 && ctrl_held == 0,
	   "a LISTEN sent over the extended protocol is accepted and pins the connection"
	   " (accepted=%s, ConnUsed=%ld, plain extended query held=%ld)",
	   accepted ? "yes" : "no", held, ctrl_held);

	notifyChannel(notifier.get(), ch, "via-extended");
	std::vector<Notification> got = drain_notifications(listener.get(), 3000);
	ok(got.size() == 1 && got[0].channel == ch && got[0].payload == "via-extended",
	   "and its notification is delivered (got %zu)", got.size());
}

// The one path where a LISTEN is refused after the gate allowed it: the session held no
// backend connection when the statement arrived, so the answer depended on a connection it
// did not have yet, and the pool then handed it a libpq one. That refusal happens mid-flight
// and unwinds the session by hand -- ends the request, empties the status stack, disposes of
// the connection -- so what matters is that the client gets a real error AND the session is
// still usable, not merely that the LISTEN was refused.
static void scenario_listen_on_pooled_libpq_conn(PGconn* admin, const std::vector<ServerRow>& saved) {
	// One connection only, so the LISTEN below cannot be handed a fresh native one.
	if (!setVar(admin, "pgsql-multiplexing", "true") ||
	    !setVar(admin, "pgsql-use_native_backend_protocol", "false") ||
	    !flushBackendPool(admin, BACKEND_HG, saved, "1")) {
		ok(false, "pooled-libpq setup failed");
		ok(false, "pooled-libpq setup failed");
		setVar(admin, "pgsql-use_native_backend_protocol", "true");
		return;
	}
	{	// leave a libpq connection behind in the pool
		PGConnPtr warm = open_client_conn();
		if (warm && PQstatus(warm.get()) == CONNECTION_OK) execSQL(warm.get(), "SELECT 1");
	}
	waitConnUsed(admin, 0, 5000);
	// Native from here on, but a pooled connection keeps the protocol it was opened with.
	if (!setVar(admin, "pgsql-use_native_backend_protocol", "true")) {
		ok(false, "pooled-libpq could not switch protocol");
		ok(false, "pooled-libpq could not switch protocol");
		return;
	}

	PGConnPtr c = open_client_conn();
	if (!c || PQstatus(c.get()) != CONNECTION_OK) {
		ok(false, "pooled-libpq could not connect");
		ok(false, "pooled-libpq could not connect");
		return;
	}
	const std::string ch = chan("poolpq");
	PGresult* r = PQexec(c.get(), ("LISTEN " + ch).c_str());
	const char* ss = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	const std::string sqlstate = ss ? ss : "";
	const bool refused = (PQresultStatus(r) == PGRES_FATAL_ERROR) && (sqlstate == "0A000");
	PQclear(r);
	ok(refused, "a LISTEN handed a pooled libpq connection is refused with 0A000 (got '%s')",
	   sqlstate.empty() ? "no error" : sqlstate.c_str());

	std::string val;
	const QRes rc = query_with_deadline(c.get(), "SELECT 42", 5000, &val);
	const long held = waitConnUsed(admin, 0, 5000);
	ok(rc == Q_OK && val == "42" && held == 0,
	   "and the session still works afterwards, holding nothing (%s, ConnUsed=%ld)",
	   qres_name(rc), held);
}

// A routing rule sends the pinned session's next query to another hostgroup, so it ends
// up holding two backend connections: the notification must keep arriving on the first,
// and the second must not be dragged into the pin. The other server is the same
// PostgreSQL reached by address rather than hostname, which gives it its own row and its
// own pool. Routing is read back from the digest and the pool counters, or the query
// could quietly stay on the first hostgroup and prove nothing.
static void scenario_second_hostgroup(PGconn* admin, PGconn* be, const std::vector<ServerRow>& saved) {
	const int OTHER_HG = 1;
	const std::vector<ServerRow> saved_other = readServers(admin, OTHER_HG);
	const std::string other_host = scalar(be, "SELECT host(inet_server_addr())");
	const std::string other_port = saved_other.empty() ? saved[0].port : saved_other[0].port;
	if (!setVar(admin, "pgsql-multiplexing", "true") || !flushBackendPool(admin, BACKEND_HG, saved) ||
	    other_host.empty() || other_host == saved[0].hostname) {
		for (int i = 0; i < 3; i++)
			ok(false, "second-hostgroup setup failed (other server address '%s')", other_host.c_str());
		return;
	}

	// A server row of its own, so hostgroup 1 is not just another name for the same
	// entry: different address, different pool, different backend connection.
	execSQL(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(OTHER_HG));
	execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	execSQL(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment)"
	               " VALUES (" + std::to_string(OTHER_HG) + ",'" + other_host + "'," + other_port +
	               ",10,0,'listen cross-hostgroup probe')");
	execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	const std::string marker = "ll_hg1_probe_" + std::to_string(getpid());
	execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8821");
	execSQL(admin, "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
	               " VALUES (8821," + std::to_string(1) + ",'AS " + marker + "'," + std::to_string(OTHER_HG) + ",1)");
	execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

	const std::string ch = chan("hg");
	PGConnPtr listener = open_client_conn();
	PGConnPtr notifier = open_client_conn();
	if (!listener || PQstatus(listener.get()) != CONNECTION_OK ||
	    !notifier || PQstatus(notifier.get()) != CONNECTION_OK ||
	    !execSQL(listener.get(), "LISTEN " + ch)) {
		for (int i = 0; i < 3; i++) ok(false, "second-hostgroup scenario could not subscribe");
		execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8821");
		execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
		flushBackendPool(admin, OTHER_HG, saved_other);
		return;
	}
	waitConnUsed(admin, 1, 5000);

	std::string probe_val;
	const QRes probe_rc = query_with_deadline(listener.get(), ("SELECT 42 AS " + marker).c_str(), 5000, &probe_val);
	const std::string probe_hg = scalar(admin,
	    "SELECT hostgroup FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + marker + "%' LIMIT 1");
	const std::string other_queries = scalar(admin,
	    "SELECT Queries FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(OTHER_HG) +
	    " AND srv_host='" + other_host + "'");
	ok(probe_rc == Q_OK && probe_val == "42" && probe_hg == std::to_string(OTHER_HG) &&
	   !other_queries.empty() && atol(other_queries.c_str()) > 0,
	   "the pinned subscriber's next query is served by the other hostgroup's other server"
	   " (%s, hostgroup '%s', %s:%s served %s queries)",
	   qres_name(probe_rc), probe_hg.c_str(), other_host.c_str(), other_port.c_str(),
	   other_queries.empty() ? "0" : other_queries.c_str());

	// Raised after the excursion: the subscription lives on the connection the session
	// left behind, and that connection is the one that has to keep being read.
	notifyChannel(notifier.get(), ch, "cross-hg");
	std::vector<Notification> got = drain_notifications(listener.get(), 3000);
	ok(got.size() == 1 && got[0].channel == ch && got[0].payload == "cross-hg",
	   "the subscriber still receives its notification while holding connections to two servers (got %zu)",
	   got.size());

	// Only the subscribed connection may stay out of the pool. The other server's
	// connection has no subscription, so it has to be multiplexed back.
	const long total = waitConnUsed(admin, 1, 5000);
	const std::string other_used = scalar(admin,
	    "SELECT SUM(ConnUsed) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(OTHER_HG));
	ok(total == 1 && (other_used.empty() || atol(other_used.c_str()) == 0),
	   "only the subscribed connection stays pinned, the other server's goes back to its pool"
	   " (held in total=%ld, held on hostgroup %d=%s)",
	   total, OTHER_HG, other_used.empty() ? "0" : other_used.c_str());

	listener.reset();
	notifier.reset();
	execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8821");
	execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	flushBackendPool(admin, OTHER_HG, saved_other);
}

int main(int, char**) {
	// delivery: scenario A 2 x 2 modes, scenario B 1 x 2 modes plus cached 2 x 2 modes.
	const int DELIVERY_ASSERTIONS = 4 + 2 + 4;
	// pin lifecycle, buffered, disconnect, backend killed, TLS, many listeners, COPY,
	// multi-statement LISTEN, notification during a query, second hostgroup
	const int LIFECYCLE_ASSERTIONS = 6 + 2 + 4 + 2 + 2 + 2 + 1 + 1 + 2 + 2 + 2 + 3;
	plan(DELIVERY_ASSERTIONS + LIFECYCLE_ASSERTIONS);
	if (cl.getEnv()) return exit_status();
	// The proxy closes the client socket when a backend is killed under a pinned
	// connection; a write landing after that must surface as an error instead of
	// killing the test process.
	signal(SIGPIPE, SIG_IGN);

	std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
		BAIL_OUT("Cannot open ProxySQL log at %s", log_path.c_str());
		return exit_status();
	}
	PGConnPtr admin = open_admin_conn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connect failed");
		return exit_status();
	}
	PGConnPtr be = open_backend_conn();
	if (!be || PQstatus(be.get()) != CONNECTION_OK) {
		BAIL_OUT("direct backend connect failed: %s", PQerrorMessage(be.get()));
		return exit_status();
	}
	std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers in hostgroup %d", BACKEND_HG);
		return exit_status();
	}
	diag("Backend under test (hg %d): %s:%s", BACKEND_HG,
	     saved[0].hostname.c_str(), saved[0].port.c_str());

	for (bool native : { false, true }) {
		scenario_pinned_session(admin.get(), native, saved);
	}
	for (bool native : { false, true }) {
		scenario_pooled_conn_leaks_nothing(admin.get(), native, saved, false);
	}
	for (bool native : { false, true }) {
		scenario_pooled_conn_leaks_nothing(admin.get(), native, saved, true);
	}

	// The lifecycle half is native only: LISTEN is refused on the libpq path.
	if (setVar(admin.get(), "pgsql-use_native_backend_protocol", "true")) {
		scenario_pin_lifecycle(admin.get(), saved);
		scenario_buffered_between_queries(admin.get(), saved);
		scenario_client_disconnect(admin.get(), be.get(), saved);
		scenario_backend_killed(admin.get(), be.get(), saved);
		scenario_tls_backend(admin.get(), be.get(), saved);
		scenario_many_listeners(admin.get(), saved);
		scenario_copy_on_pinned(admin.get(), saved);
		scenario_multi_statement_listen_not_tracked(admin.get(), saved);
		scenario_notification_during_query(admin.get(), saved);
		scenario_extended_protocol_listen(admin.get(), saved);
		scenario_listen_on_pooled_libpq_conn(admin.get(), saved);
		scenario_second_hostgroup(admin.get(), be.get(), saved);
	} else {
		for (int i = 0; i < LIFECYCLE_ASSERTIONS; i++) ok(false, "cannot switch to the native backend protocol");
	}

	// Leave the proxy the way the group expects to find it.
	setVar(admin.get(), "pgsql-multiplexing", "true");
	setVar(admin.get(), "pgsql-use_native_backend_protocol", "false");
	flushBackendPool(admin.get(), BACKEND_HG, saved);
	return exit_status();
}
