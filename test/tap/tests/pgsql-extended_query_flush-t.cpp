/**
 * @file pgsql-extended_query_flush-t.cpp
 * @brief A client Flush ('H') in the PostgreSQL extended query protocol behaves as in PostgreSQL.
 *
 * A Flush asks the server for the replies to everything sent so far, without ending the group of
 * messages: no ReadyForQuery, the implicit transaction stays open, portals stay alive, and the
 * client ends the group later with its own Sync. postgres.js sends Parse + Describe + Flush for
 * every query with an untyped parameter, node-postgres cursors page a portal with
 * Execute(n) + Flush, and libpq pipeline mode has PQsendFlushRequest().
 *
 * Every case runs in the three backend modes:
 *   - LIBPQ: pgsql-use_native_backend_protocol off;
 *   - NATIVE: on, so a group goes to the backend in batches;
 *   - NATIVE_UNBATCHED: on, but the client sets an untracked startup option, which keeps the
 *     session's first group one message at a time.
 * Pooled connections keep the mode they were opened in, so the pool is emptied after every switch,
 * and each mode must land on a backend pid the previous mode did not use.
 *
 * Expected reply sequences were taken from PostgreSQL 17 directly
 * (docs/superpowers/specs/2026-10-26-pgsql-client-flush-design.md, section 2).
 * Replies are read until the socket stays quiet; a closed socket fails the case.
 * Configuration is only loaded to runtime, never saved to disk.
 */
#include <chrono>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // MUST precede utils.h (mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using Msgs = std::vector<std::pair<char, std::vector<uint8_t>>>;
CommandLine cl;

static const int HG = 0;
static const int QUIET_MS = 300;

enum class Mode { LIBPQ, NATIVE, NATIVE_UNBATCHED };

static const char* mode_name(Mode m) {
	switch (m) {
	case Mode::LIBPQ: return "libpq";
	case Mode::NATIVE: return "native";
	default: return "native-unbatched";
	}
}

static PGConnPtr open_conn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const bool good = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

// Direct connection to PostgreSQL, in the database the client uses (named after the user).
static PGConnPtr backend() {
	return open_conn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
		cl.pgsql_server_password, cl.pgsql_username);
}

// Empties the pool: pooled connections keep the protocol they were opened with, so after a mode
// switch they must go, or the next mode quietly reuses them.
static void reset_pool(PGconn* admin) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
		|| !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s down", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (std::chrono::steady_clock::now() < deadline) {
		const std::string n = scalar(admin,
			"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg);
		if (!n.empty() && atoi(n.c_str()) == 0) break;
		usleep(100000);
	}
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
		|| !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

static bool set_mode(PGconn* admin, Mode m) {
	const std::string want = (m == Mode::LIBPQ) ? "false" : "true";
	if (!exec(admin, "SET pgsql-use_native_backend_protocol='" + want + "'")
		|| !exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME"))
		return false;
	const std::string got = scalar(admin, "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'");
	reset_pool(admin);
	return got == want;
}

static std::unique_ptr<PgConnection> client(Mode m) {
	auto c = std::make_unique<PgConnection>(5000);
	// An untracked startup option keeps the session's first group one message at a time.
	if (m == Mode::NATIVE_UNBATCHED) c->setOptions("-c work_mem=4MB");
	c->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	return c;
}

static std::string field(const std::vector<uint8_t>& b, char code) {
	size_t i = 0;
	while (i < b.size() && b[i] != 0) {
		const char k = (char)b[i++];
		std::string v;
		while (i < b.size() && b[i] != 0) v += (char)b[i++];
		i++;
		if (k == code) return v;
	}
	return "";
}

// Reply messages as space-separated tokens: Z(status), E(sqlstate), C(tag), the type byte otherwise.
// ParameterStatus and NoticeResponse are left out: they may come at any point and answer nothing.
static std::string tokens(const Msgs& msgs) {
	std::string out;
	for (const auto& m : msgs) {
		std::string t;
		switch (m.first) {
		case 'S': case 'N': continue;
		case 'Z': t = std::string("Z(") + (m.second.empty() ? '?' : (char)m.second[0]) + ")"; break;
		case 'E': t = "E(" + field(m.second, 'C') + ")"; break;
		case 'C': t = "C(" + std::string(m.second.begin(), m.second.end() - (m.second.empty() ? 0 : 1)) + ")"; break;
		default: t = std::string(1, m.first);
		}
		if (!out.empty()) out += ' ';
		out += t;
	}
	return out;
}

// Sends, then returns the replies that arrive before the socket goes quiet. A connection that is
// closed or broken is reported as such, never as "no reply".
static std::string run(PgConnection& c, const std::function<void()>& send, int quiet_ms = QUIET_MS) {
	try {
		send();
		return tokens(c.readUntilQuiet(quiet_ms));
	} catch (const PgException& e) {
		return std::string("CLOSED:") + e.what();
	}
}

// The backend pid of the connection this session runs on. The bare pg_backend_pid() is answered by
// ProxySQL itself, so it is read from pg_stat_activity.
static std::string proxy_pid(PgConnection& c) {
	try {
		c.sendQuery("SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()");
		std::string pid;
		for (const auto& m : c.readUntilQuiet(QUIET_MS)) {
			if (m.first == 'D' && m.second.size() > 6) {
				const auto& b = m.second;
				const int32_t len = (b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5];
				if (len > 0 && (size_t)(6 + len) <= b.size()) pid.assign(b.begin() + 6, b.begin() + 6 + len);
			}
		}
		return pid;
	} catch (const PgException&) {
		return "";
	}
}

// Statement text new to this run: ProxySQL answers a Parse of text it already knows by itself, which
// changes the reply path under test.
static std::string uniq() {
	static long n = 0;
	return "/*flush-" + std::to_string((long)time(nullptr)) + "-" + std::to_string(++n) + "*/ ";
}

static void check(const std::string& got, const std::string& want, const char* what, Mode m, bool txn) {
	ok(got == want, "%s [%s%s]: got '%s', expected '%s'", what, mode_name(m), txn ? ", in txn" : "",
		got.c_str(), want.c_str());
}

// BEGIN as a simple Query, when the case runs inside an explicit transaction.
static void maybe_begin(PgConnection& c, bool txn) {
	if (txn) run(c, [&] { c.sendQuery("BEGIN"); });
}

static char txn_z(bool txn) { return txn ? 'T' : 'I'; }

// ===== Cases. Each makes exactly the number of ok() calls in its CASES row. =====

// Control: the same statement ended by Sync, which works today.
static void case_sync_control(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string z = std::string("Z(") + txn_z(txn) + ")";
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT $1::text AS x", false); c->describeStatement("", true); }),
		"1 t T " + z, "sync control: P D(S) S", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false); c->executePortal("", 0, true); }),
		"2 D C(SELECT 1) " + z, "sync control: B E S", m, txn);
}

// Row 1, postgres.js: Parse + Describe(statement) + Flush, then Bind + Execute + Sync.
static void case_row1(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string z = std::string("Z(") + txn_z(txn) + ")";
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT $1 AS x", false); c->describeStatement("", false); c->sendFlush(); }),
		"1 t T", "row 1: P D(S) H", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false); c->executePortal("", 0, true); }),
		"2 D C(SELECT 1) " + z, "row 1: B E S", m, txn);
}

static const char* SER = "SELECT g FROM generate_series(1,5) g";
static const std::string ALL5 = "D D D D D C(SELECT 5)";

// Admin and a direct backend connection, for cases that change runtime settings or count rows.
static PGconn* g_admin = nullptr;
static PGconn* g_be = nullptr;

static long rows(const std::string& tag) {
	const std::string n = scalar(g_be, "SELECT count(*) FROM flush_t WHERE tag = '" + tag + "'");
	return n.empty() ? -1 : atol(n.c_str());
}

static std::string tag_for(const char* what, Mode m, bool txn) {
	return std::string(what) + "_" + std::to_string((int)m) + (txn ? "t" : "a") + "_" + std::to_string((long)time(nullptr));
}

// The first column of the first DataRow, as text.
static std::string first_value(const Msgs& msgs) {
	for (const auto& m : msgs) {
		if (m.first == 'D' && m.second.size() >= 6) {
			const auto& b = m.second;
			const int32_t len = (b[2] << 24) | (b[3] << 16) | (b[4] << 8) | b[5];
			if (len > 0 && (size_t)(6 + len) <= b.size()) return std::string(b.begin() + 6, b.begin() + 6 + len);
		}
	}
	return "";
}

static bool admin_set(const std::string& var, const std::string& value) {
	return exec(g_admin, "SET " + var + "='" + value + "'") && exec(g_admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Task 3: Bind and Describe(portal) with no Execute after it. The Bind must reach the backend
// before the Describe; in libpq mode it does not (no bind-only call), a known gap.
static void case_describe_portal_no_execute(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string z = std::string("Z(") + txn_z(txn) + ")";
	const std::string got = run(*c, [&] {
		c->prepareStatement("", uniq() + "SELECT g FROM generate_series(1,3) g", false);
		c->bindStatement("", "", {}, {}, false);
		c->describePortal("", true);
	});
	if (m == Mode::LIBPQ) {
		// libpq has no bind-only call: whatever it answers, the session must survive it.
		ok(got.rfind("CLOSED", 0) != 0, "describe portal, no execute [libpq%s]: session survives (known gap, got '%s')",
			txn ? ", in txn" : "", got.c_str());
		return;
	}
	check(got, "1 2 T " + z, "describe portal, no execute: P B D(P) S", m, txn);
	check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, true); }),
		"2 D D D C(SELECT 3) " + z, "describe portal, no execute: then B E S", m, txn);
}

// Task 4: a row limit on the unnamed portal, ended by Sync. Native follows PostgreSQL; libpq keeps
// returning every row (by design) and has no suspended portal to continue.
static void case_unnamed_row_limit(Mode m, bool) {
	const bool lp = (m == Mode::LIBPQ);
	const std::string all = "D D D D D C(SELECT 5)";
	{   // (a) outside a transaction the portal ends at the Sync
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); }),
			lp ? "1 2 " + all + " Z(I)" : "1 2 D D s Z(I)", "row limit (a): P B E(2) S", m, false);
		check(run(*c, [&] { c->executePortal("", 2, true); }), "E(34000) Z(I)", "row limit (a): E(2) S after the Sync", m, false);
	}
	if (lp) return;  // (b)-(f) need a suspended portal, which libpq mode never has (by design)
	{   // (b) in a transaction the suspended portal continues
		auto c = client(m);
		maybe_begin(*c, true);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); }),
			"1 2 D D s Z(T)", "row limit (b): P B E(2) S", m, true);
		check(run(*c, [&] { c->executePortal("", 2, true); }), "D D s Z(T)", "row limit (b): E(2) S continues", m, true);
		check(run(*c, [&] { c->executePortal("", 0, true); }), "D C(SELECT 1) Z(T)", "row limit (b): E(0) S finishes", m, true);
	}
	{   // (c) Close of the suspended portal
		auto c = client(m);
		maybe_begin(*c, true);
		run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); });
		// closePortal(.., true) would read the replies itself: send the Sync separately.
		check(run(*c, [&] { c->closePortal("", false); c->sendSync(); }), "3 Z(T)", "row limit (c): C(P) S", m, true);
		check(run(*c, [&] { c->executePortal("", 2, true); }), "E(34000) Z(E)", "row limit (c): E(2) S after the Close", m, true);
	}
	{   // (d) a simple Query destroys the unnamed portal
		auto c = client(m);
		maybe_begin(*c, true);
		run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); });
		run(*c, [&] { c->sendQuery("SELECT 1"); });
		check(run(*c, [&] { c->executePortal("", 2, true); }), "E(34000) Z(E)", "row limit (d): E(2) S after a simple Query", m, true);
	}
	{   // (e) a new Bind replaces the suspended portal
		auto c = client(m);
		maybe_begin(*c, true);
		run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false); c->executePortal("", 2, true); });
		check(run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, true); }),
			"2 " + all + " Z(T)", "row limit (e): B E S replaces the portal", m, true);
	}
	{   // (f) suspended and continued inside one unit
		auto c = client(m);
		check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
				c->executePortal("", 2, false); c->executePortal("", 2, true); }),
			"1 2 D D s D D s Z(I)", "row limit (f): P B E(2) E(2) S", m, false);
	}
}

// Row 2: a whole statement before the Flush, then the Sync alone.
static void case_row2(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
			c->describePortal("", false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 T " + ALL5, "row 2: P B D(P) E H", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_z(txn) + ")", "row 2: S", m, txn);
}

// Row 3, unnamed portal: a cursor paged across Flushes. libpq returns every row (by design).
static void case_row3a(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	const std::string first = run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "", {}, {}, false);
		c->describePortal("", false); c->executePortal("", 2, false); c->sendFlush(); });
	if (m == Mode::LIBPQ) {
		check(first, "1 2 T " + ALL5, "row 3a: P B D(P) E(2) H (libpq: every row)", m, txn);
		return;
	}
	check(first, "1 2 T D D s", "row 3a: P B D(P) E(2) H", m, txn);
	check(run(*c, [&] { c->executePortal("", 2, false); c->sendFlush(); }), "D D s", "row 3a: E(2) H", m, txn);
	check(run(*c, [&] { c->executePortal("", 0, false); c->sendFlush(); }), "D C(SELECT 1)", "row 3a: E(0) H", m, txn);
	check(run(*c, [&] { c->closePortal("", false); c->sendSync(); }), std::string("3 Z(") + txn_z(txn) + ")", "row 3a: C(P) S", m, txn);
}

// Row 3, named portal (native only: libpq mode refuses named portals, see the error cases).
static void case_row3b(Mode m, bool txn) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "p1", {}, {}, false);
			c->describePortal("p1", false); c->executePortal("p1", 2, false); c->sendFlush(); }),
		"1 2 T D D s", "row 3b: P B(p1) D(P p1) E(p1,2) H", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 2, false); c->sendFlush(); }), "D D s", "row 3b: E(p1,2) H", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 0, false); c->sendFlush(); }), "D C(SELECT 1)", "row 3b: E(p1,0) H", m, txn);
	check(run(*c, [&] { c->closePortal("p1", false); c->sendSync(); }), std::string("3 Z(") + txn_z(txn) + ")", "row 3b: C(P p1) S", m, txn);
}

// Row 4: a named portal bound before a Flush and executed after it (native only).
static void case_row4(Mode m, bool txn) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + SER, false); c->bindStatement("", "p1", {}, {}, false); c->sendFlush(); }),
		"1 2", "row 4: P B(p1) H", m, txn);
	check(run(*c, [&] { c->executePortal("p1", 0, true); }), ALL5 + " Z(" + txn_z(txn) + ")", "row 4: E(p1) S", m, txn);
}

// Row 10: Flush with nothing queued, several Flushes, and a Flush between two messages.
static void case_row10(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->sendFlush(); }), "", "row 10: H alone", m, txn);
	check(run(*c, [&] { c->sendFlush(); c->sendFlush(); }), "", "row 10: H H", m, txn);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT 1", false); c->sendFlush(); c->sendFlush();
			c->describeStatement("", false); c->sendFlush(); }), "1 t T", "row 10: P H H D(S) H", m, txn);
	check(run(*c, [&] { c->sendSync(); }), std::string("Z(") + txn_z(txn) + ")", "row 10: S", m, txn);
}

// Row 12: an explicit transaction opened and written through the extended protocol across Flushes.
static void case_row12(Mode m, bool) {
	auto c = client(m);
	const std::string tag = tag_for("row12", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "BEGIN", false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); c->sendFlush(); }), "1 2 C(BEGIN)", "row 12: P(BEGIN) B E H", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 C(INSERT 0 1)", "row 12: P(INSERT) B E H", m, false);
	check(run(*c, [&] { c->sendSync(); }), "Z(T)", "row 12: S keeps the transaction", m, false);
	ok(rows(tag) == 0, "row 12 [%s]: not committed before COMMIT (rows=%ld)", mode_name(m), rows(tag));
	check(run(*c, [&] { c->sendQuery("COMMIT"); }), "C(COMMIT) Z(I)", "row 12: COMMIT", m, false);
	ok(rows(tag) == 1, "row 12 [%s]: committed by COMMIT (rows=%ld)", mode_name(m), rows(tag));
}

// The connection holding a Flush-ended group stays with it, also when connection_delay_multiplex_ms
// would otherwise hand an idle connection back to the pool after the delay.
static void case_pin_delay_multiplex(Mode m, bool) {
	admin_set("pgsql-connection_delay_multiplex_ms", "100");
	auto c = client(m);
	const std::string tag = tag_for("pin", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', pg_backend_pid())", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 C(INSERT 0 1)", "pin: P B E(INSERT) H", m, false);
	usleep(6500000);  // past the delay and past a maintenance pass (pgsql-poll_timeout)
	std::string pid2;
	try {
		c->prepareStatement("", uniq() + "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()", false);
		c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush();
		pid2 = first_value(c->readUntilQuiet(QUIET_MS));
	} catch (const PgException& e) { pid2 = std::string("CLOSED:") + e.what(); }
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "pin: S", m, false);
	const std::string pid1 = scalar(g_be, "SELECT v::text FROM flush_t WHERE tag = '" + tag + "'");
	ok(!pid1.empty() && pid1 == pid2, "pin [%s]: the group stayed on one backend across the delay (insert pid %s, later pid %s)",
		mode_name(m), pid1.c_str(), pid2.c_str());
	ok(rows(tag) == 1, "pin [%s]: the row is committed by the client's Sync (rows=%ld)", mode_name(m), rows(tag));
	admin_set("pgsql-connection_delay_multiplex_ms", "0");
}

// Row 16: a Flush changes nothing in the digest statistics. The same two Executes with a Sync
// in place of the Flush give the control count (ProxySQL counts the Parse too).
static void case_row16_stats(Mode m, bool) {
	auto count = [&](bool flush) {
		const std::string alias = std::string(flush ? "flush16h_" : "flush16s_") + std::to_string((int)m) + "_" + std::to_string((long)time(nullptr));
		auto c = client(m);
		run(*c, [&] { c->prepareStatement("", "SELECT 1 AS " + alias, false); c->bindStatement("", "", {}, {}, false);
			c->executePortal("", 0, false); if (flush) c->sendFlush(); else c->sendSync(); });
		run(*c, [&] { c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, true); });
		return scalar(g_admin, "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + alias + "%'");
	};
	const std::string with_sync = count(false), with_flush = count(true);
	ok(with_sync != "0" && with_flush == with_sync, "row 16 [%s]: P B E H + B E S counted as P B E S + B E S (Flush %s, Sync %s)",
		mode_name(m), with_flush.c_str(), with_sync.c_str());
}

// Review focus: every message in one TCP write.
static void case_one_write(Mode m, bool txn) {
	auto c = client(m);
	maybe_begin(*c, txn);
	check(run(*c, [&] { c->beginBuffering(); c->prepareStatement("", uniq() + "SELECT $1::text AS x", false);
			c->describeStatement("", false); c->sendFlush(); c->bindStatement("", "", { { std::string("a"), 0 } }, {}, false);
			c->executePortal("", 0, true); c->endBuffering(); }),
		std::string("1 t T 2 D C(SELECT 1) Z(") + txn_z(txn) + ")", "one write: P D(S) H B E S", m, txn);
}

// Review focus: a result larger than threshold_resultset_size inside a Flush-ended segment.
static void case_large_result(Mode m, bool) {
	auto c = client(m);
	int d = 0; std::string last; bool z = false;
	try {
		c->prepareStatement("", uniq() + "SELECT g FROM generate_series(1,100000) g", false);
		c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush();
		for (const auto& msg : c->readUntilQuiet(1000)) {
			if (msg.first == 'D') d++;
			else if (msg.first == 'Z') z = true;
			else last = tokens(Msgs{ msg });
		}
	} catch (const PgException& e) { last = std::string("CLOSED:") + e.what(); }
	ok(d == 100000 && last == "C(SELECT 100000)" && !z, "large result [%s]: 100000 rows, CommandComplete, no ReadyForQuery (rows=%d, last='%s', Z=%d)",
		mode_name(m), d, last.c_str(), (int)z);
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "large result: S", m, false);
}

// Review focus: native mode switched on while a libpq connection holds a group.
static void case_mode_flip_mid_group(Mode m, bool) {
	if (m != Mode::LIBPQ) return;
	auto c = client(m);
	const std::string tag = tag_for("flip", m, false);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "INSERT INTO flush_t VALUES ('" + tag + "', 1)", false);
			c->bindStatement("", "", {}, {}, false); c->executePortal("", 0, false); c->sendFlush(); }),
		"1 2 C(INSERT 0 1)", "mode flip: P B E(INSERT) H on libpq", m, false);
	admin_set("pgsql-use_native_backend_protocol", "true");
	check(run(*c, [&] { c->sendSync(); }), "Z(I)", "mode flip: S after native mode was switched on", m, false);
	ok(rows(tag) == 1, "mode flip [libpq]: the group finished on its own connection (rows=%ld)", rows(tag));
	admin_set("pgsql-use_native_backend_protocol", "false");
}

// Review focus: a long cursor, one row per Execute + Flush (native only).
static void case_long_cursor(Mode m, bool) {
	if (m == Mode::LIBPQ) return;
	auto c = client(m);
	check(run(*c, [&] { c->prepareStatement("", uniq() + "SELECT g FROM generate_series(1,1000) g", false);
			c->bindStatement("", "p1", {}, {}, false); c->describePortal("p1", false); c->sendFlush(); }),
		"1 2 T", "long cursor: P B(p1) D(P p1) H", m, false);
	int good = 0;
	try {
		for (int i = 0; i < 1000; i++) {
			c->executePortal("p1", 1, false); c->sendFlush();
			char t1 = 0, t2 = 0; std::vector<uint8_t> b;
			c->readMessage(t1, b); c->readMessage(t2, b);
			if (t1 == 'D' && t2 == 's') good++;
		}
	} catch (const PgException& e) { diag("long cursor [%s]: %s", mode_name(m), e.what()); }
	ok(good == 1000, "long cursor [%s]: 1000 x E(p1,1) H each gave D s (%d did)", mode_name(m), good);
	check(run(*c, [&] { c->closePortal("p1", false); c->sendSync(); }), "3 Z(I)", "long cursor: C(P p1) S", m, false);
}

struct Case {
	const char* name;
	int checks;        // ok() calls per (mode, txn) run
	int checks_libpq;  // the same in libpq mode, where some behaviour is out of scope by design
	bool both_txn;     // also run inside BEGIN
	std::function<void(Mode, bool)> fn;
};

static const std::vector<Case> CASES = {
	{ "sync control",                2,  2, true,  case_sync_control },
	{ "row 1",                       2,  2, true,  case_row1 },
	{ "describe portal, no execute", 2,  1, true,  case_describe_portal_no_execute },
	{ "unnamed row limit",           10, 2, false, case_unnamed_row_limit },
	{ "row 2",                       2,  2, true,  case_row2 },
	{ "row 3a",                      4,  1, true,  case_row3a },
	{ "row 3b",                      4,  0, true,  case_row3b },
	{ "row 4",                       2,  0, true,  case_row4 },
	{ "row 10",                      4,  4, true,  case_row10 },
	{ "row 12",                      6,  6, false, case_row12 },
	{ "pin across delay multiplex",  4,  4, false, case_pin_delay_multiplex },
	{ "row 16 stats",                1,  1, false, case_row16_stats },
	{ "one write",                   1,  1, true,  case_one_write },
	{ "large result",                2,  2, false, case_large_result },
	{ "mode flip mid group",         0,  3, false, case_mode_flip_mid_group },
	{ "long cursor",                 3,  0, false, case_long_cursor },
};

static const Mode MODES[] = { Mode::LIBPQ, Mode::NATIVE, Mode::NATIVE_UNBATCHED };

int main(int, char**) {
	if (cl.getEnv()) return exit_status();

	int total = 0;
	for (const Mode m : MODES) {
		total += 1;  // the mode-switch check
		for (const Case& k : CASES) total += (m == Mode::LIBPQ ? k.checks_libpq : k.checks) * (k.both_txn ? 2 : 1);
	}
	plan(total);

	auto admin = open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	const std::string native_before = scalar(admin.get(), "SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'");

	auto be = backend();
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no direct backend connection");
	g_admin = admin.get();
	g_be = be.get();
	exec(g_be, "DROP TABLE IF EXISTS flush_t");
	if (!exec(g_be, "CREATE TABLE flush_t (tag text, v int)"))
		BAIL_OUT("could not create flush_t");
	exec(g_be, std::string("GRANT ALL ON flush_t TO ") + cl.pgsql_username);

	std::string prev_pid;
	for (const Mode m : MODES) {
		const bool switched = set_mode(admin.get(), m);
		std::string pid;
		{
			auto c = client(m);
			pid = proxy_pid(*c);
		}
		ok(switched && !pid.empty() && pid != prev_pid, "mode %s in effect on a new backend (pid %s, previous %s)",
			mode_name(m), pid.c_str(), prev_pid.empty() ? "-" : prev_pid.c_str());
		prev_pid = pid;
		for (const Case& k : CASES) {
			for (int t = 0; t < (k.both_txn ? 2 : 1); t++) {
				try {
					k.fn(m, t == 1);
				} catch (const PgException& e) {
					diag("%s [%s]: %s", k.name, mode_name(m), e.what());
				}
			}
		}
	}

	exec(g_be, "DROP TABLE IF EXISTS flush_t");
	exec(admin.get(), "SET pgsql-use_native_backend_protocol='" + (native_before.empty() ? std::string("false") : native_before) + "'");
	exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	return exit_status();
}
