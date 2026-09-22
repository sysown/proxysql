/**
 * @file pgsql-native_mixed_pool-t.cpp
 * @brief Both backend protocols alive at once, which is what an operator creates by
 *        turning pgsql-use_native_backend_protocol on at runtime.
 *
 * A pooled connection keeps the protocol it was opened with, so flipping the variable
 * does not convert anything: the pool holds libpq connections and every new one is
 * native. Successive statements from one client then land on either, and a session can
 * hold one of each at the same time across two hostgroups.
 *
 * Every other native test flushes the pool after flipping the variable, precisely so this
 * cannot happen -- a differential test that skips the flush silently runs libpq twice.
 * That leaves the mixed state itself untested, which is what this file covers.
 *
 * Which protocol served a statement is established from PostgreSQL, not from ProxySQL:
 * the pids of the connections opened in libpq mode are recorded first, and every later
 * statement is matched back to a pid through pg_stat_activity. An assertion that both
 * kinds were used is what stops the rest from passing on a uniform pool.
 *
 * INFRA: legacy-g1 (docker-pgsql16-single).
 */

#include <string>
#include <sstream>
#include <vector>
#include <set>
#include <memory>
#include <cstring>
#include <ctime>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
static const int BACKEND_HG = 0;
static const int OTHER_HG = 1;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr open_admin_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password;
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr open_client_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// Straight to PostgreSQL: which backend ran a statement is not something to ask the
// component under test.
static PGConnPtr open_backend_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port
	   << " user=" << cl.pgsql_server_username << " password=" << cl.pgsql_server_password
	   << " dbname=postgres";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execSQL(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	const ExecStatusType st = PQresultStatus(res);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
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

// Rebuilding the server row drops every pooled connection, which is how each phase starts
// from a pool whose protocol is known.
static bool freshPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved,
                      const std::string& max_conns_override = "") {
	if (saved.empty()) return false;
	if (!execSQL(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		const std::string mc = max_conns_override.empty()
			? (r.max_connections.empty() ? std::string("50") : r.max_connections)
			: max_conns_override;
		if (!execSQL(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment)"
		                    " VALUES (" + std::to_string(hg) + ",'" + r.hostname + "'," + r.port + ","
		                    + mc + "," + r.use_ssl + ",'" + r.comment + "')")) return false;
	}
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(300000);
	return true;
}

static long connUsed(PGconn* admin) {
	const std::string v = scalar(admin, "SELECT SUM(ConnUsed) FROM stats_pgsql_connection_pool");
	return v.empty() ? -1 : atol(v.c_str());
}

static long waitConnUsed(PGconn* admin, long expected, int timeout_ms) {
	int waited = 0;
	long v = connUsed(admin);
	while (v != expected && waited < timeout_ms) { usleep(100000); waited += 100; v = connUsed(admin); }
	return v;
}

// The backend that last ran a statement carrying `marker`, straight from PostgreSQL.
static int backendPidForMarker(PGconn* be, const std::string& marker) {
	const std::string v = scalar(be,
	    "SELECT pid FROM pg_stat_activity WHERE backend_type='client backend'"
	    " AND pid <> pg_backend_pid() AND query LIKE '%" + marker + "%' LIMIT 1");
	return v.empty() ? -1 : atoi(v.c_str());
}

static std::string mark(const char* tag) {
	return std::string("mix_") + tag + "_" + std::to_string(getpid());
}

// Runs a marker query on a client and reports which backend served it.
static int runAndIdentify(PGconn* be, PGconn* c, const std::string& marker, bool& ok_out) {
	PGresult* r = PQexec(c, ("SELECT 42 AS " + marker).c_str());
	ok_out = (PQresultStatus(r) == PGRES_TUPLES_OK) && (std::string(PQgetvalue(r, 0, 0)) == "42");
	PQclear(r);
	return backendPidForMarker(be, marker);
}

// ---------------------------------------------------------------------------
// Fill the pool in libpq mode, switch to native without flushing, then work through it.
// ---------------------------------------------------------------------------
static void scenario_mixed_pool(PGconn* admin, PGconn* be, const std::vector<ServerRow>& saved) {
	if (!setVar(admin, "pgsql-multiplexing", "true") ||
	    !setVar(admin, "pgsql-use_native_backend_protocol", "false") ||
	    !freshPool(admin, BACKEND_HG, saved, "6")) {
		for (int i = 0; i < 4; i++) ok(false, "mixed pool setup failed");
		return;
	}

	// Two libpq connections held at the same time. Without the transaction the first one
	// returns to the pool before the second client asks for it, and both statements land on
	// one connection -- a pool of one, and nothing to mix later.
	std::set<int> libpq_pids;
	{
		PGConnPtr a = open_client_conn();
		PGConnPtr b = open_client_conn();
		bool oka = false, okb = false;
		if (a && PQstatus(a.get()) == CONNECTION_OK && b && PQstatus(b.get()) == CONNECTION_OK) {
			execSQL(a.get(), "BEGIN");
			const int pa = runAndIdentify(be, a.get(), mark("warm1"), oka);
			const int pb = runAndIdentify(be, b.get(), mark("warm2"), okb);
			execSQL(a.get(), "COMMIT");
			if (pa > 0) libpq_pids.insert(pa);
			if (pb > 0) libpq_pids.insert(pb);
		}
		if (!oka || !okb || libpq_pids.size() != 2) {
			for (int i = 0; i < 4; i++) ok(false, "could not warm two libpq connections (got %zu pids)", libpq_pids.size());
			setVar(admin, "pgsql-use_native_backend_protocol", "false");
			return;
		}
	}
	waitConnUsed(admin, 0, 5000);
	diag("libpq connections parked in the pool: %d and %d", *libpq_pids.begin(), *libpq_pids.rbegin());

	// From here every NEW connection is native, while the two above stay libpq.
	if (!setVar(admin, "pgsql-use_native_backend_protocol", "true")) {
		for (int i = 0; i < 4; i++) ok(false, "could not switch protocol");
		return;
	}

	// Three clients at once against a pool holding two: the third has to open a new
	// connection, which is native, so both kinds are in use at the same moment.
	std::vector<PGConnPtr> clients;
	std::set<int> seen_pids;
	int good = 0;
	for (int i = 0; i < 3; i++) {
		PGConnPtr c = open_client_conn();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) continue;
		// Each holds its connection for the duration, so all three are in use together:
		// two of them find the pooled libpq connections, the third has to open a native one.
		execSQL(c.get(), "BEGIN");
		bool q_ok = false;
		const int pid = runAndIdentify(be, c.get(), mark(("m" + std::to_string(i)).c_str()), q_ok);
		if (q_ok) good++;
		if (pid > 0) seen_pids.insert(pid);
		clients.push_back(std::move(c));
	}
	for (auto& c : clients) execSQL(c.get(), "COMMIT");
	int reused = 0, fresh = 0;
	for (int p : seen_pids) (libpq_pids.count(p) ? reused : fresh)++;

	ok(good == 3, "every statement is answered correctly while both protocols were in the pool (%d/3)", good);
	ok(reused >= 1 && fresh >= 1,
	   "and both kinds of connection really served traffic (%d pooled libpq, %d new native)",
	   reused, fresh);

	// One session, several statements, landing on whichever connection is free: the
	// results must not depend on which protocol served them.
	PGConnPtr roamer = open_client_conn();
	std::set<int> roamer_pids;
	int roamer_ok = 0;
	if (roamer && PQstatus(roamer.get()) == CONNECTION_OK) {
		for (int i = 0; i < 6; i++) {
			bool q_ok = false;
			const int pid = runAndIdentify(be, roamer.get(), mark(("r" + std::to_string(i)).c_str()), q_ok);
			if (q_ok) roamer_ok++;
			if (pid > 0) roamer_pids.insert(pid);
		}
	}
	ok(roamer_ok == 6, "one session gets the same answer whichever connection serves it (%d/6)", roamer_ok);

	// State that lives on a connection must survive being carried across a mixed pool.
	bool txn_ok = false, stmt_ok = false, err_ok = false;
	if (roamer && PQstatus(roamer.get()) == CONNECTION_OK) {
		txn_ok = execSQL(roamer.get(), "BEGIN") &&
		         execSQL(roamer.get(), "CREATE TEMP TABLE mix_t(i int)") &&
		         execSQL(roamer.get(), "INSERT INTO mix_t VALUES (7)") &&
		         (scalar(roamer.get(), "SELECT sum(i) FROM mix_t") == "7") &&
		         execSQL(roamer.get(), "COMMIT") &&
		         (scalar(roamer.get(), "SELECT sum(i) FROM mix_t") == "7");

		PGresult* pr = PQprepare(roamer.get(), "mix_ps", "SELECT $1::int + 1", 1, NULL);
		const bool prepared = (PQresultStatus(pr) == PGRES_COMMAND_OK);
		PQclear(pr);
		const char* vals[1] = { "41" };
		PGresult* er = PQexecPrepared(roamer.get(), "mix_ps", 1, vals, NULL, NULL, 0);
		stmt_ok = prepared && (PQresultStatus(er) == PGRES_TUPLES_OK) &&
		          (std::string(PQgetvalue(er, 0, 0)) == "42");
		PQclear(er);

		PGresult* bad = PQexec(roamer.get(), "SELECT * FROM mix_no_such_table");
		const char* ss = PQresultErrorField(bad, PG_DIAG_SQLSTATE);
		err_ok = (PQresultStatus(bad) == PGRES_FATAL_ERROR) && ss && (std::string(ss) == "42P01");
		PQclear(bad);
		err_ok = err_ok && (scalar(roamer.get(), "SELECT 1") == "1");
	}
	ok(txn_ok && stmt_ok && err_ok,
	   "transactions, prepared statements and errors behave across a mixed pool"
	   " (txn=%s, prepared=%s, error=%s)",
	   txn_ok ? "ok" : "BAD", stmt_ok ? "ok" : "BAD", err_ok ? "ok" : "BAD");
}

// ---------------------------------------------------------------------------
// One session holding a libpq connection in one hostgroup and a native one in the other.
// ---------------------------------------------------------------------------
static void scenario_one_of_each_at_once(PGconn* admin, PGconn* be, const std::vector<ServerRow>& saved) {
	const std::vector<ServerRow> saved_other = readServers(admin, OTHER_HG);
	if (saved_other.empty() ||
	    !setVar(admin, "pgsql-multiplexing", "true") ||
	    !setVar(admin, "pgsql-use_native_backend_protocol", "false") ||
	    !freshPool(admin, BACKEND_HG, saved, "6") ||
	    !freshPool(admin, OTHER_HG, saved_other, "6")) {
		ok(false, "one-of-each setup failed");
		ok(false, "one-of-each setup failed");
		return;
	}

	// hostgroup 0 gets a libpq connection...
	int libpq_pid = -1;
	{
		PGConnPtr warm = open_client_conn();
		bool q_ok = false;
		if (warm && PQstatus(warm.get()) == CONNECTION_OK)
			libpq_pid = runAndIdentify(be, warm.get(), mark("hg0warm"), q_ok);
	}
	waitConnUsed(admin, 0, 5000);

	// ...and hostgroup 1 will get native ones, because the switch happens before it is used.
	setVar(admin, "pgsql-use_native_backend_protocol", "true");
	const std::string marker = mark("hg1");
	execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8851");
	execSQL(admin, "INSERT INTO pgsql_query_rules (rule_id,active,match_digest,destination_hostgroup,apply)"
	               " VALUES (8851,1,'AS " + marker + "'," + std::to_string(OTHER_HG) + ",1)");
	execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

	PGConnPtr c = open_client_conn();
	bool hg0_ok = false, hg1_ok = false;
	int hg0_pid = -1, hg1_pid = -1;
	if (c && PQstatus(c.get()) == CONNECTION_OK) {
		hg0_pid = runAndIdentify(be, c.get(), mark("hg0"), hg0_ok);   // pooled libpq
		PGresult* r = PQexec(c.get(), ("SELECT 42 AS " + marker).c_str());
		hg1_ok = (PQresultStatus(r) == PGRES_TUPLES_OK) && (std::string(PQgetvalue(r, 0, 0)) == "42");
		PQclear(r);
		hg1_pid = backendPidForMarker(be, marker);
	}
	const std::string hg1_used = scalar(admin,
	    "SELECT SUM(Queries) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(OTHER_HG));
	ok(hg0_ok && hg1_ok && hg0_pid > 0 && hg1_pid > 0 && hg0_pid != hg1_pid,
	   "one session is served by two different backends, one per hostgroup (pids %d and %d)",
	   hg0_pid, hg1_pid);
	ok(hg0_pid == libpq_pid && !hg1_used.empty() && atol(hg1_used.c_str()) > 0,
	   "the first is the connection opened in libpq mode, the second is a native one"
	   " (libpq pid %d reused=%s, hostgroup %d queries=%s)",
	   libpq_pid, hg0_pid == libpq_pid ? "yes" : "no", OTHER_HG,
	   hg1_used.empty() ? "0" : hg1_used.c_str());

	c.reset();
	execSQL(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=8851");
	execSQL(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	freshPool(admin, OTHER_HG, saved_other);
}

int main(int, char**) {
	plan(4 + 2);
	if (cl.getEnv()) return exit_status();

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
	const std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
	if (saved.empty()) {
		BAIL_OUT("No pgsql_servers in hostgroup %d", BACKEND_HG);
		return exit_status();
	}

	scenario_mixed_pool(admin.get(), be.get(), saved);
	scenario_one_of_each_at_once(admin.get(), be.get(), saved);

	// Leave the proxy the way the group expects to find it.
	setVar(admin.get(), "pgsql-use_native_backend_protocol", "false");
	setVar(admin.get(), "pgsql-multiplexing", "true");
	freshPool(admin.get(), BACKEND_HG, saved);
	return exit_status();
}
