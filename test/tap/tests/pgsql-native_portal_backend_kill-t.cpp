/**
 * @file pgsql-native_portal_backend_kill-t.cpp
 * @brief What a client is told when the backend connection holding its NAMED
 *        PORTAL is killed underneath it (native backend protocol).
 *
 * The session's portal registry is session state describing ONE backend
 * connection. This test kills that connection from outside -- pg_terminate_backend
 * from a direct libpq connection -- while a named portal is open and suspended,
 * then drives the client forward and records what it actually receives.
 *
 * What is asserted, in order of what matters:
 *   1. the client is TOLD. No DataRow may come back for a portal whose connection
 *      died: silently restarting a half-read result is the failure mode worth
 *      catching, an error is not.
 *   2. the proxy survives the kill and keeps serving.
 *   3. the client can recover -- rebind the portal and read the whole result.
 *   4. the registry is not left describing the dead connection: re-executing the
 *      dead portal never returns rows.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single, scram-sha-256, no TLS).
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <cstring>
#include <csignal>
#include <thread>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // MUST precede utils.h: mysql.h defines a PROTOCOL_VERSION macro
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static const int PG_TIMEOUT_MS = 8000;
static const char* MARKER = "portal_kill_marker";
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// --------------------------------------------------------------------------
// admin plumbing (mirrors pgsql-native_portals-t)
// --------------------------------------------------------------------------
static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	ExecStatusType st = PQresultStatus(res);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
	PQclear(res);
	return good;
}

static std::string adminScalar(PGconn* admin, const std::string& q) {
	PGresult* res = PQexec(admin, q.c_str());
	std::string v;
	if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0 && !PQgetisnull(res, 0, 0))
		v = PQgetvalue(res, 0, 0);
	PQclear(res);
	return v;
}

struct ServerRow { std::string hostname, port, max_connections, comment; };

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
	std::vector<ServerRow> rows;
	PGresult* res = PQexec(admin,
	    ("SELECT hostname, port, max_connections, comment FROM pgsql_servers "
	     "WHERE hostgroup_id=" + std::to_string(hg)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(res); i++) {
			ServerRow r;
			r.hostname = PQgetvalue(res, i, 0);
			r.port = PQgetvalue(res, i, 1);
			r.max_connections = PQgetvalue(res, i, 2);
			r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
			rows.push_back(std::move(r));
		}
	}
	PQclear(res);
	return rows;
}

// Recreate every pooled connection in the CURRENT mode: a warm libpq-mode pool
// would make the named Bind hit the libpq rejection and test nothing.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
	if (saved.empty()) return false;
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		std::string ins = "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) VALUES ("
			+ std::to_string(hg) + ",'" + r.hostname + "'," + r.port + ","
			+ (r.max_connections.empty() ? std::string("1000") : r.max_connections)
			+ ",'" + r.comment + "')";
		if (!execAdmin(admin, ins)) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

// Frontend cleartext so pg_lite_client can reach the proxy. BAIL_OUT skips
// destructors, so every exit path after construction calls restore() first.
struct AuthMethodScope {
	PGconn* admin;
	std::string saved;
	bool restored = false;
	explicit AuthMethodScope(PGconn* a) : admin(a) {
		saved = adminScalar(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-authentication_method'");
		if (saved.empty()) { diag("cannot read pgsql-authentication_method"); return; }
		execAdmin(admin, "SET pgsql-authentication_method=1");
		execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	void restore() {
		if (restored) return;
		restored = true;
		if (saved.empty()) return;
		execAdmin(admin, "SET pgsql-authentication_method=" + saved);
		execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	~AuthMethodScope() { restore(); }
};

struct NativeModeScope {
	PGconn* admin;
	std::string saved;
	bool restored = false;
	explicit NativeModeScope(PGconn* a) : admin(a) {
		saved = adminScalar(admin,
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
		execAdmin(admin, "SET pgsql-use_native_backend_protocol='true'");
		execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	void restore() {
		if (restored) return;
		restored = true;
		if (saved.empty()) return;
		execAdmin(admin, "SET pgsql-use_native_backend_protocol='" + saved + "'");
		execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	}
	~NativeModeScope() { restore(); }
};

// --------------------------------------------------------------------------
// wire helpers
// --------------------------------------------------------------------------
static std::unique_ptr<PgConnection> connectProxy() {
	auto c = std::make_unique<PgConnection>(PG_TIMEOUT_MS);
	c->connect(cl.pgsql_host, cl.pgsql_port, "postgres",
	           cl.pgsql_root_username, cl.pgsql_root_password);
	return c;
}

// ErrorResponse/NoticeResponse body: (fieldType byte, C-string)*, 0 terminated.
// 'C' carries the SQLSTATE.
static std::string errSqlstate(const std::vector<uint8_t>& body) {
	size_t i = 0;
	while (i < body.size() && body[i] != 0) {
		char f = (char)body[i++];
		std::string v;
		while (i < body.size() && body[i] != 0) v += (char)body[i++];
		if (i < body.size()) i++;  // skip the field NUL
		if (f == 'C') return v;
	}
	return "";
}

// Read one cycle's messages up to ReadyForQuery. Returns a compact trace; sets
// `closed` if the proxy dropped the client connection instead of answering.
struct Cycle {
	std::string trace;
	std::string sqlstate;
	int rows = 0;
	bool closed = false;
	// A backend-generated ErrorResponse carries source-location fields ('F' file,
	// 'L' line, 'R' routine); one ProxySQL builds locally does not. That is how a
	// registry miss answered by the proxy is told apart from an Execute that was
	// forwarded to a backend which never had the portal.
	bool err_from_backend = false;
};

static bool errHasSourceFields(const std::vector<uint8_t>& body) {
	size_t i = 0;
	while (i < body.size() && body[i] != 0) {
		char f = (char)body[i++];
		while (i < body.size() && body[i] != 0) i++;
		if (i < body.size()) i++;
		if (f == 'F' || f == 'L' || f == 'R') return true;
	}
	return false;
}

static Cycle readCycle(PgConnection& c) {
	Cycle out;
	try {
		for (;;) {
			char t = 0;
			std::vector<uint8_t> b;
			c.readMessage(t, b);
			if (t == PgConnection::PARAMETER_STATUS) continue;
			if (t == PgConnection::DATA_ROW) out.rows++;
			out.trace += t;
			if (t == PgConnection::ERROR_RESPONSE || t == PgConnection::NOTICE_RESPONSE) {
				std::string ss = errSqlstate(b);
				if (t == PgConnection::ERROR_RESPONSE) {
					if (out.sqlstate.empty()) out.sqlstate = ss;
					out.err_from_backend = errHasSourceFields(b);
				}
				out.trace += "{" + ss + "}";
			}
			if (t == PgConnection::READY_FOR_QUERY) {
				if (!b.empty()) out.trace += "(" + std::string(1, (char)b[0]) + ")";
				break;
			}
		}
	} catch (const std::exception& e) {
		out.closed = true;
		out.trace += "<connection closed>";
	}
	return out;
}

// Kill the backend serving our portal, from a DIRECT connection to PostgreSQL.
// pg_backend_pid() through the proxy is intercepted and fabricated, so the pid
// is found by the marker left in the statement text instead.
static bool killBackendRunningMarker(std::string& why) {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port
	   << " user=" << cl.pgsql_root_username << " password=" << cl.pgsql_root_password
	   << " dbname=postgres";
	PGConnPtr be(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(be.get()) != CONNECTION_OK) {
		why = std::string("direct backend connect failed: ") + PQerrorMessage(be.get());
		return false;
	}
	std::string q = "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
	                "WHERE query LIKE '%" + std::string(MARKER) + "%' "
	                "AND pid <> pg_backend_pid() AND backend_type='client backend'";
	PGresult* res = PQexec(be.get(), q.c_str());
	bool killed = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0);
	if (!killed) why = "no backend matched the marker";
	PQclear(res);
	return killed;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) { diag("Failed to get the required environment variables"); return -1; }
	// The proxy closes the client socket on some of these paths; a write that lands
	// after that must surface as an error, not kill the test process.
	signal(SIGPIPE, SIG_IGN);
	plan(9);

	PGConnPtr admin = open_admin_conn();
	if (PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("admin connection failed");

	std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	AuthMethodScope auth(admin.get());
	NativeModeScope native(admin.get());
	if (!flushBackendPool(admin.get(), BACKEND_HG, saved)) {
		native.restore(); auth.restore();
		BAIL_OUT("could not flush the backend pool");
	}

	const std::string q_fast = "SELECT i FROM generate_series(1,5) i /* " + std::string(MARKER) + " */";
	const std::string q_slow = "SELECT i, pg_sleep(1) FROM generate_series(1,5) i /* " + std::string(MARKER) + " */";

	// ---------------------------------------------------------------- case A
	// Backend killed while the session sits IDLE with a suspended portal, which
	// is where a client pauses between reads.
	Cycle a_first, a_after;
	bool a_killed = false;
	std::string a_why;
	try {
		auto c = connectProxy();
		c->execute("BEGIN");
		c->consumeInputUntilReady();
		c->prepareStatement("stA", q_fast, false);
		c->bindStatement("stA", "pkA", {}, {}, false);
		c->executePortal("pkA", 2, true);
		a_first = readCycle(*c);

		a_killed = killBackendRunningMarker(a_why);
		usleep(500000);

		try {
			c->executePortal("pkA", 2, true);
			a_after = readCycle(*c);
		} catch (const std::exception& e) {
			a_after.closed = true;
			a_after.trace += "<send failed: connection closed>";
		}
		if (!a_after.closed) c->disconnect();
	} catch (const std::exception& e) {
		diag("case A exception: %s", e.what());
	}

	// ---------------------------------------------------------------- case B
	// Backend killed while an Execute on the portal is IN FLIGHT. This is the
	// path where ProxySQL can keep the client session alive (25P02), so the
	// portal registry outlives the connection it described -- the case the fix
	// is about.
	Cycle b_first, b_after, b_reread, b_after_rollback, b_recover;
	bool b_killed = false, proxy_alive = false;
	std::string b_why;
	try {
		auto c = connectProxy();
		c->execute("BEGIN");
		c->consumeInputUntilReady();
		c->prepareStatement("stB", q_slow, false);
		c->bindStatement("stB", "pkB", {}, {}, false);
		c->executePortal("pkB", 1, true);   // ~1s: one row, one pg_sleep
		b_first = readCycle(*c);

		std::thread killer([&]{ usleep(800000); b_killed = killBackendRunningMarker(b_why); });
		try {
			c->executePortal("pkB", 2, true);   // ~2s, killed in the middle
			b_after = readCycle(*c);
		} catch (const std::exception& e) {
			b_after.closed = true;
			b_after.trace += "<send failed: connection closed>";
		}
		killer.join();

		if (!b_after.closed) {
			// Session survived. Ask the dead portal for rows again -- a stale
			// registry entry would make the proxy skip the Bind and execute it
			// on a connection that never had it.
			try {
				c->executePortal("pkB", 2, true);
				b_reread = readCycle(*c);
			} catch (const std::exception& e) {
				b_reread.closed = true;
			}
			if (!b_reread.closed) {
				// Out of the aborted transaction the 25P02 shield is gone, so this
				// Execute reaches the portal registry itself.
				c->execute("ROLLBACK");
				c->consumeInputUntilReady();
				try {
					c->executePortal("pkB", 2, true);
					b_after_rollback = readCycle(*c);
				} catch (const std::exception& e) {
					b_after_rollback.closed = true;
				}
				if (!b_after_rollback.closed) c->disconnect();
			}
		}
	} catch (const std::exception& e) {
		diag("case B exception: %s", e.what());
	}

	// -------------------------------------------------- recovery + liveness
	try {
		auto c2 = connectProxy();
		c2->prepareStatement("stR", q_fast, false);
		c2->bindStatement("stR", "pkB", {}, {}, false);
		c2->executePortal("pkB", 0, true);
		b_recover = readCycle(*c2);
		c2->execute("SELECT 42");
		auto r = c2->readResult();
		proxy_alive = (r && r->rowCount() == 1);
		c2->disconnect();
	} catch (const std::exception& e) {
		diag("recovery exception: %s", e.what());
	}

	diag("A baseline          : %s (rows=%d)", a_first.trace.c_str(), a_first.rows);
	diag("A after idle kill   : %s (rows=%d, sqlstate='%s', client connection %s)",
	     a_after.trace.c_str(), a_after.rows, a_after.sqlstate.c_str(),
	     a_after.closed ? "DROPPED" : "alive");
	diag("B baseline          : %s (rows=%d)", b_first.trace.c_str(), b_first.rows);
	diag("B after inflight kill: %s (rows=%d, sqlstate='%s', client connection %s)",
	     b_after.trace.c_str(), b_after.rows, b_after.sqlstate.c_str(),
	     b_after.closed ? "DROPPED" : "alive");
	diag("B dead portal reread: %s (rows=%d, sqlstate='%s')",
	     b_reread.trace.c_str(), b_reread.rows, b_reread.sqlstate.c_str());
	diag("B portal after ROLLBACK: %s (rows=%d, sqlstate='%s', error built by %s)",
	     b_after_rollback.trace.c_str(), b_after_rollback.rows, b_after_rollback.sqlstate.c_str(),
	     b_after_rollback.err_from_backend ? "the BACKEND" : "the proxy");
	diag("recovery            : %s (rows=%d)", b_recover.trace.c_str(), b_recover.rows);

	ok(a_first.rows == 2 && a_first.trace.find('s') != std::string::npos,
		"A: named portal returns 2 rows and suspends [%s]", a_first.trace.c_str());
	ok(a_killed, "A: the backend holding the portal was terminated %s", a_why.c_str());
	ok(a_after.rows == 0 && (a_after.closed || !a_after.sqlstate.empty()),
		"A: client gets no rows and is told [%s]", a_after.trace.c_str());

	ok(b_first.rows == 1 && b_first.trace.find('s') != std::string::npos,
		"B: named portal returns 1 row and suspends [%s]", b_first.trace.c_str());
	ok(b_killed, "B: the backend was terminated while the Execute was in flight %s", b_why.c_str());
	ok(b_after.rows == 0 && (b_after.closed || !b_after.sqlstate.empty()),
		"B: client gets no rows and is told [%s]", b_after.trace.c_str());
	// The fix: nothing may answer for a portal whose connection is gone.
	ok(b_reread.rows == 0,
		"B: re-executing the portal whose backend died returns no rows [%s]",
		b_reread.trace.c_str());
	// The registry must have dropped the portal with its connection. If it had not,
	// the proxy would treat pkB as still bound, skip the Bind and forward the Execute
	// to a backend that never had it -- which shows up as a BACKEND-generated error
	// instead of the proxy's own undefined-cursor reply.
	ok(b_after_rollback.rows == 0 && b_after_rollback.sqlstate == "34000" &&
		b_after_rollback.err_from_backend == false,
		"B: after ROLLBACK the dead portal is unknown to the proxy itself [%s, built by %s]",
		b_after_rollback.trace.c_str(), b_after_rollback.err_from_backend ? "BACKEND" : "proxy");
	ok(proxy_alive && b_recover.rows == 5,
		"proxy survives and a rebind of the same portal name returns all 5 rows (rows=%d, alive=%d)",
		b_recover.rows, (int)proxy_alive);

	native.restore();
	auth.restore();
	return exit_status();
}
