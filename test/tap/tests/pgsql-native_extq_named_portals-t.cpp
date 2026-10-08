/**
 * @file pgsql-native_extq_named_portals-t.cpp
 * @brief Named portals in native extended-query units: what the client receives must be what
 *        PostgreSQL itself sends for the same frame.
 *
 * Each case sends one frame twice, through ProxySQL with the native backend protocol and
 * directly to PostgreSQL, and compares what comes back, message by message. The libpq path
 * cannot be the reference here: it refuses named portals.
 *
 * These pass on the one-message-at-a-time path and must keep passing once named portals are
 * batched: they pin the client-visible behaviour, not how the frame reaches the backend
 * (pgsql-native_extq_named_portals_mock-t checks that).
 *
 * Needs a hostgroup 0 PostgreSQL reachable directly at TAP_PGSQLSERVER_*.
 */

#include <chrono>
#include <ctime>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // raw frontend messages (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int HG = 0;
static std::string tag;   // per run, so every run starts from statement texts no backend has seen

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
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
static long execLong(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	long v = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) v = atol(PQgetvalue(r, 0, 0));
	PQclear(r);
	return v;
}

// Taking the servers down and back drops every pooled connection, so the next frame runs on a
// connection that holds none of the statements prepared so far.
static void resetPool(PGconn* admin) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s down", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (std::chrono::steady_clock::now() < deadline) {
		if (execLong(admin, "SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg) == 0) break;
		usleep(100000);
	}
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

static long connUsed(PGconn* admin) {
	return execLong(admin, "SELECT COALESCE(SUM(ConnUsed),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(HG));
}

static std::string errorSqlstate(const std::vector<uint8_t>& payload) {
	size_t i = 0;
	while (i < payload.size() && payload[i] != 0) {
		const char code = (char)payload[i++];
		const size_t start = i;
		while (i < payload.size() && payload[i] != 0) i++;
		if (code == 'C') return std::string((const char*)payload.data() + start, i - start);
		if (i < payload.size()) i++;
	}
	return "";
}

// What the client receives up to the ReadyForQuery, one token per message: "1 2 T D=1 s Z(T)".
// A DataRow shows its first column, an error only its SQLSTATE (ProxySQL builds some errors
// itself, with other text), a ReadyForQuery its status. Notices and parameter changes are left
// out: they answer no message.
static std::string replies(PgConnection& c) {
	std::string out;
	for (;;) {
		char type = 0;
		std::vector<uint8_t> buf;
		c.readMessage(type, buf);
		if (type == 'N' || type == 'S') continue;
		if (!out.empty()) out += ' ';
		out += type;
		if (type == 'D' && buf.size() >= 6) {
			const int32_t len = (int32_t)((buf[2] << 24) | (buf[3] << 16) | (buf[4] << 8) | buf[5]);
			out += "=" + (len < 0 ? std::string("NULL") : std::string((const char*)buf.data() + 6, len));
		} else if (type == 'E') {
			out += "(" + errorSqlstate(buf) + ")";
		} else if (type == 'Z' && buf.size() >= 1) {
			out += std::string("(") + (char)buf[0] + ")";
			break;
		}
	}
	return out;
}

static std::string simple(PgConnection& c, const std::string& sql) {
	c.sendQuery(sql);
	return replies(c);
}

static PgConnection::Param text(const std::string& v) { return PgConnection::Param{ v, 0 }; }

// A frame, written once and run on both connections. It returns the replies of every unit it
// sends, separated by " | ".
using Frame = std::function<std::string(PgConnection&)>;

static std::string run(Frame f, bool through_proxy) {
	try {
		PgConnection c(5000);
		if (through_proxy) {
			c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		} else {
			c.connect(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_username, cl.pgsql_server_username, cl.pgsql_server_password);
		}
		return f(c);
	} catch (const PgException& e) {
		return std::string("threw: ") + e.what();
	}
}

// Two assertions per case: the replies are the ones expected, and they are PostgreSQL's own.
static void check(const char* label, const std::string& expected, Frame f) {
	const std::string proxy = run(f, true);
	const std::string direct = run(f, false);
	ok(proxy == expected, "%s: replies [%s] expected [%s]", label, proxy.c_str(), expected.c_str());
	ok(proxy == direct, "%s: same as PostgreSQL [proxy: %s] [PostgreSQL: %s]", label, proxy.c_str(), direct.c_str());
}

int main(int, char**) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}
	plan(54);
	tag = std::to_string(getpid()) + "_" + std::to_string(time(nullptr) % 100000);

	PGConnPtr admin = openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
	if (PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("cannot reach the admin interface");
	if (!exec(admin.get(), "SET pgsql-use_native_backend_protocol='true'") || !exec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"))
		BAIL_OUT("could not turn the native protocol on");
	resetPool(admin.get());   // pooled libpq connections would not take named portals

	const std::string five = "SELECT g FROM generate_series(1, 5) AS g";

	// N1: Bind and Execute of a named portal in one unit.
	check("N1 named Bind + Execute", "1 2 D=7 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n1_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N2: a Describe of the portal right before its Execute.
	check("N2 named Describe folded into Execute", "1 2 T D=7 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n2_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.describePortal("p1", false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N3: the cursor pattern -- a portal opened in one unit and fetched page by page in later ones.
	// N3b: while it is open the connection stays with the session.
	long used_while_open = -1;
	check("N3 fetch a named portal page by page",
		"C Z(T) | 1 2 T D=1 D=2 s Z(T) | D=3 D=4 s Z(T) | D=5 C Z(T) | 3 Z(T) | C Z(I)", [&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		c.prepareStatement("s", five + " /* n3_" + tag + " */", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.describePortal("p1", false);
		c.executePortal("p1", 2, false);
		c.sendSync();
		out += " | " + replies(c);
		if (used_while_open == -1) {   // the proxy run comes first
			usleep(300000);
			used_while_open = connUsed(admin.get());
		}
		for (int i = 0; i < 2; i++) {
			c.executePortal("p1", 2, false);
			c.sendSync();
			out += " | " + replies(c);
		}
		c.closePortal("p1", false);
		c.sendSync();
		out += " | " + replies(c);
		return out + " | " + simple(c, "COMMIT");
	});
	ok(used_while_open == 1, "N3b an open portal keeps the backend connection with the session [ConnUsed=%ld]", used_while_open);

	// N4: two portals in one unit, their Executes interleaved.
	check("N4 two named portals, interleaved", "1 2 2 D=1 s D=1 s D=2 D=3 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT g FROM generate_series(1, 3) AS g /* n4_" + tag + " */", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.bindStatement("s", "p2", {}, {}, false);
		c.executePortal("p1", 1, false);
		c.executePortal("p2", 1, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N5: Close then Execute of the same portal in one unit.
	check("N5 Execute after Close in the same unit", "1 2 D=7 C 3 E(34000) Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n5_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.closePortal("p1", false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N6: Binding a name that is already open fails, and the transaction is then aborted.
	check("N6 re-Bind of an open portal", "C Z(T) | 1 2 D=1 s Z(T) | E(42P03) Z(E) | E(25P02) Z(E) | C Z(I)", [&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		c.prepareStatement("s", five + " /* n6_" + tag + " */", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 1, false);
		c.sendSync();
		out += " | " + replies(c);
		c.bindStatement("s", "p1", {}, {}, false);
		c.sendSync();
		out += " | " + replies(c);
		c.executePortal("p1", 1, false);
		c.sendSync();
		out += " | " + replies(c);
		return out + " | " + simple(c, "ROLLBACK");
	});

	// N7: a Bind that fails leaves no portal behind.
	check("N7 failed named Bind registers nothing", "1 E(08P01) Z(I) | E(34000) Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT $1::int AS n7_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);   // one parameter expected, none given
		c.sendSync();
		std::string out = replies(c);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return out + " | " + replies(c);
	});

	// N8: a portal does not outlive its transaction.
	check("N8 portal gone after COMMIT", "C Z(T) | 1 2 Z(T) | C Z(I) | E(34000) Z(I)", [&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		c.prepareStatement("s", "SELECT 7 AS n8_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.sendSync();
		out += " | " + replies(c);
		out += " | " + simple(c, "COMMIT");
		c.executePortal("p1", 0, false);
		c.sendSync();
		return out + " | " + replies(c);
	});

	// N9: closing a portal that was never bound.
	check("N9 Close of an unknown portal", "3 Z(I)", [&](PgConnection& c) {
		c.closePortal("px", false);
		c.sendSync();
		return replies(c);
	});

	// N10: an error earlier in the unit skips the named Bind after it, so no portal exists later.
	// random() keeps the division from being folded at Bind: the error must come from Execute.
	check("N10 error before a named Bind", "1 2 E(22012) Z(I) | E(34000) Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s1", "SELECT 1 / (random() * $1::int)::int AS n10_" + tag, false);
		c.bindStatement("s1", "", { text("0") }, {}, false);
		c.executePortal("", 0, false);
		c.prepareStatement("s2", "SELECT 7 AS n10b_" + tag, false);
		c.bindStatement("s2", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		std::string out = replies(c);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return out + " | " + replies(c);
	});

	// N11: a statement the global cache knows, on a connection that does not hold it: ProxySQL
	// prepares it there before the named Bind.
	{
		const std::string known = "SELECT 7 AS n11_" + tag;
		run([&](PgConnection& c) { c.prepareStatement("warm", known, false); c.sendSync(); return replies(c); }, true);
		resetPool(admin.get());
		check("N11 known statement, connection without it", "1 2 D=7 C Z(I)", [&](PgConnection& c) {
			c.prepareStatement("s", known, false);
			c.bindStatement("s", "p1", {}, {}, false);
			c.executePortal("p1", 0, false);
			c.sendSync();
			return replies(c);
		});
	}

	// N12: a SET run through a named portal takes effect for what follows.
	check("N12 SET through a named portal", "1 2 C Z(I) | T D=3 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SET extra_float_digits TO 3", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		std::string out = replies(c);
		return out + " | " + simple(c, "SELECT current_setting('extra_float_digits')");
	});

	// N13: a SET Parsed in an earlier unit, then bound and run through a named portal. The SET
	// stops the batch at the Execute; the Bind before it must already count as open.
	check("N13 SET Parsed earlier, run through a named portal", "1 Z(I) | 2 C Z(I) | T D=3 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SET extra_float_digits TO 3", false);
		c.sendSync();
		std::string out = replies(c);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		out += " | " + replies(c);
		return out + " | " + simple(c, "SELECT current_setting('extra_float_digits')");
	});

	// N14: closing the statement a portal was bound from leaves the portal open.
	check("N14 portal outlives its statement's Close", "1 2 3 D=7 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n14_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.closeStatement("s", false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N15: a Describe of a named portal that no Execute of it follows.
	check("N15 Describe of a named portal on its own", "1 2 T 3 Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n15_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.describePortal("p1", false);
		c.closePortal("p1", false);
		c.sendSync();
		return replies(c);
	});

	// N16: a query rule refuses a statement after a named Bind in the same unit. The replies before
	// it and the error reach the client; the connection holding the unfinished unit is dropped, and
	// the portal with it. ProxySQL only: PostgreSQL has no rules.
	{
		exec(admin.get(), "INSERT INTO pgsql_query_rules (rule_id, active, match_digest, error_msg, apply) VALUES "
			"(7801, 1, 'refused_" + tag + "', 'refused by rule', 1)");
		exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
		const std::string got = run([&](PgConnection& c) {
			c.prepareStatement("s", "SELECT 7 AS n16_" + tag, false);
			c.bindStatement("s", "p1", {}, {}, false);
			c.prepareStatement("r", "SELECT 8 AS refused_" + tag, false);
			c.sendSync();
			std::string out = replies(c);
			c.executePortal("p1", 0, false);
			c.sendSync();
			return out + " | " + replies(c);
		}, true);
		exec(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=7801");
		exec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
		ok(got == "1 2 E(42501) Z(I) | E(34000) Z(I)",
		   "N16 a rule refuses a statement after a named Bind: error, then the portal is gone [%s]", got.c_str());
	}

	// N17: inside a transaction, a later unit runs a portal, closes it and runs it again. PostgreSQL
	// answers 34000 and the transaction is failed until ROLLBACK.
	check("N17 Close then Execute of an earlier portal, in a transaction",
		"C Z(T) | 1 2 D=1 s Z(T) | D=2 s 3 E(34000) Z(E) | C Z(I)", [&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		c.prepareStatement("s", five + " /* n17_" + tag + " */", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 1, false);
		c.sendSync();
		out += " | " + replies(c);
		c.executePortal("p1", 1, false);
		c.closePortal("p1", false);
		c.executePortal("p1", 1, false);
		c.sendSync();
		out += " | " + replies(c);
		return out + " | " + simple(c, "ROLLBACK");
	});

	// N18: a named Bind with a text parameter and a binary result column: the Bind goes out as the
	// client sent it, only the statement name changes. The row is int4 42 in binary.
	check("N18 named Bind with a parameter and a binary result", "1 2 D=" + std::string("\0\0\0*", 4) + " C Z(I)",
		[&](PgConnection& c) {
		c.prepareStatement("s", "SELECT $1::int + 1 AS n18_" + tag, false);
		c.bindStatement("s", "p1", { text("41") }, { 1 }, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N19: the backend fails the Execute of a portal opened in the same unit, inside a transaction.
	// The portal exists until ROLLBACK ends the transaction, then it is gone.
	check("N19 backend error after a named Bind, in a transaction",
		"C Z(T) | 1 2 E(22012) Z(E) | C Z(I) | E(34000) Z(I)", [&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		c.prepareStatement("s", "SELECT 1 / (random() * 0)::int AS n19_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		out += " | " + replies(c);
		out += " | " + simple(c, "ROLLBACK");
		c.executePortal("p1", 0, false);
		c.sendSync();
		return out + " | " + replies(c);
	});

	// N20: ROLLBACK TO SAVEPOINT destroys a portal opened after the savepoint; PostgreSQL then
	// refuses it and the transaction is failed.
	check("N20 savepoint rollback destroys a later portal",
		"C Z(T) | C Z(T) | 1 2 D=1 s Z(T) | C Z(T) | E(34000) Z(E) | C Z(I)", [&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		out += " | " + simple(c, "SAVEPOINT sp1");
		c.prepareStatement("s", five + " /* n20_" + tag + " */", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 1, false);
		c.sendSync();
		out += " | " + replies(c);
		out += " | " + simple(c, "ROLLBACK TO SAVEPOINT sp1");
		c.executePortal("p1", 1, false);
		c.sendSync();
		out += " | " + replies(c);
		return out + " | " + simple(c, "ROLLBACK");
	});

	// N21: Close and Bind the same name again in one unit.
	check("N21 Close and re-Bind a name in one unit", "1 2 D=7 C 3 2 D=7 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n21_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.closePortal("p1", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N22: three units sent back to back without reading in between, the later ones using the
	// portal the first opens.
	check("N22 pipelined units sharing a portal", "C Z(T) | 1 2 D=1 s Z(T) | D=2 s Z(T) | 3 Z(T) | C Z(I)",
		[&](PgConnection& c) {
		std::string out = simple(c, "BEGIN");
		c.prepareStatement("s", five + " /* n22_" + tag + " */", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 1, false);
		c.sendSync();
		c.executePortal("p1", 1, false);
		c.sendSync();
		c.closePortal("p1", false);
		c.sendSync();
		for (int i = 0; i < 3; i++) out += " | " + replies(c);
		return out + " | " + simple(c, "COMMIT");
	});

	// N23: an empty statement run through a named portal answers EmptyQueryResponse.
	check("N23 empty statement through a named portal", "1 2 I Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "", false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N24: a hundred portals opened and run in one unit.
	{
		std::string expected = "1";
		for (int i = 0; i < 100; i++) expected += " 2";
		for (int i = 0; i < 100; i++) expected += " D=7 C";
		expected += " Z(I)";
		check("N24 a hundred named portals in one unit", expected, [&](PgConnection& c) {
			c.prepareStatement("s", "SELECT 7 AS n24_" + tag, false);
			for (int i = 0; i < 100; i++) c.bindStatement("s", "p" + std::to_string(i), {}, {}, false);
			for (int i = 0; i < 100; i++) c.executePortal("p" + std::to_string(i), 0, false);
			c.sendSync();
			return replies(c);
		});
	}

	// N25: a Describe of one portal followed by an Execute of another is not folded into it.
	check("N25 Describe of one portal, Execute of another", "1 2 2 T D=7 C D=7 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n25_" + tag, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.bindStatement("s", "p2", {}, {}, false);
		c.describePortal("p1", false);
		c.executePortal("p2", 0, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N26: the unnamed portal, then a named one, in one unit.
	check("N26 unnamed then named portal in one unit", "1 2 D=7 C 2 D=7 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s", "SELECT 7 AS n26_" + tag, false);
		c.bindStatement("s", "", {}, {}, false);
		c.executePortal("", 0, false);
		c.bindStatement("s", "p1", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.sendSync();
		return replies(c);
	});

	// N27: a named portal run while the unnamed portal is bound and waiting for its own Execute.
	check("N27 named Execute between the unnamed Bind and its Execute", "1 1 2 2 D=7 C D=8 C Z(I)", [&](PgConnection& c) {
		c.prepareStatement("s1", "SELECT 7 AS n27_" + tag, false);
		c.prepareStatement("s2", "SELECT 8 AS n27b_" + tag, false);
		c.bindStatement("s1", "p1", {}, {}, false);
		c.bindStatement("s2", "", {}, {}, false);
		c.executePortal("p1", 0, false);
		c.executePortal("", 0, false);
		c.sendSync();
		return replies(c);
	});

	return exit_status();
}
