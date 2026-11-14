/**
 * @file pgsql-hold_cursor_pinning-t.cpp
 * @brief A WITH HOLD cursor must stay with the client that declared it.
 *
 * A cursor declared WITH HOLD survives COMMIT and lives on the backend connection. ProxySQL
 * used to put that connection back in the pool with the cursor still open, so the next client
 * handed it could FETCH the first client's rows, move its position, or fail to declare a
 * cursor of the same name.
 *
 * Every scenario flushes the pool first, so the client that declares the cursor holds the only
 * backend connection. That is what makes "another client lands on a different backend" mean
 * the connection was kept, and "the next client lands on the same backend" mean the cursor was
 * really closed, instead of the pool happening to offer another connection. Backend pids come
 * from pg_stat_activity: a bare pg_backend_pid() is answered by ProxySQL itself.
 *
 * Every scenario runs on the native backend protocol and on libpq.
 *
 * INFRA: legacy-g1.
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <functional>
#include <ctime>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;
static const int BACKEND_HG = 0;
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
	PGConnPtr c(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(c.get()) != CONNECTION_OK) diag("client connect failed: %s", PQerrorMessage(c.get()));
	return c;
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

// First column of every row, comma separated; "<error>" when the statement fails.
static std::string rows_csv(PGconn* c, const std::string& q) {
	PGresult* res = PQexec(c, q.c_str());
	if (PQresultStatus(res) != PGRES_TUPLES_OK) {
		PQclear(res);
		return "<error>";
	}
	std::string out;
	for (int i = 0; i < PQntuples(res); i++) {
		if (i) out += ",";
		out += PQgetvalue(res, i, 0);
	}
	PQclear(res);
	return out;
}

static bool execParams(PGconn* c, const char* sql, const char* param) {
	PGresult* res = PQexecParams(c, sql, 1, nullptr, &param, nullptr, nullptr, 0);
	bool good = PQresultStatus(res) == PGRES_COMMAND_OK;
	if (!good) diag("failed: %s -- %s", sql, PQerrorMessage(c));
	PQclear(res);
	return good;
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

static uint64_t now_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)(ts.tv_nsec / 1000000);
}

static long poolSum(PGconn* admin, const char* col) {
	const std::string v = scalar(admin, std::string("SELECT SUM(") + col + ") FROM stats_pgsql_connection_pool");
	return v.empty() ? -1 : atol(v.c_str());
}

// Waits up to timeout_ms for ConnUsed to reach 'expected' and returns the last value seen.
// Asserting that a connection stays held means waiting for it to be released and seeing it
// was not.
static long waitConnUsed(PGconn* admin, long expected, int timeout_ms) {
	const uint64_t deadline = now_ms() + timeout_ms;
	long v = poolSum(admin, "ConnUsed");
	while (v != expected && now_ms() < deadline) {
		usleep(50000);
		v = poolSum(admin, "ConnUsed");
	}
	return v;
}

// Drops every pooled connection: deleting the servers sends them OFFLINE_HARD, which closes the
// free ones at once. A connection still held by a client that has just gone would come back into
// the pool once the servers are re-added, so that wait comes first, and the pool must end empty.
// New connections also pick up the current pgsql-use_native_backend_protocol, which pooled ones never do.
static bool flushBackendPool(PGconn* admin, const std::vector<ServerRow>& saved) {
	if (saved.empty()) return false;
	const long held = waitConnUsed(admin, 0, 5000);
	if (held != 0) {
		diag("pool flush: %ld connections still in use", held);
		return false;
	}
	if (!execSQL(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(BACKEND_HG))) return false;
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& r : saved) {
		const std::string mc = r.max_connections.empty() ? std::string("1000") : r.max_connections;
		if (!execSQL(admin, "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) VALUES ("
			+ std::to_string(BACKEND_HG) + ",'" + r.hostname + "'," + r.port + "," + mc + "," + r.use_ssl
			+ ",'" + r.comment + "')")) return false;
	}
	if (!execSQL(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(300000);
	const long left = poolSum(admin, "ConnUsed") + poolSum(admin, "ConnFree");
	if (left != 0) diag("pool flush: %ld connections left in the pool", left);
	return left == 0;
}

static int backendPid(PGconn* c) {
	const std::string v = scalar(c, "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()");
	return v.empty() ? -1 : atoi(v.c_str());
}

static PGconn* g_admin = nullptr;
static std::vector<ServerRow> g_servers;
static std::string g_mode;

static const char* SERIES = "SELECT g FROM generate_series(1,6) g";

// Runs fn with pgsql-query_digests_keep_comment on, so the digest starts with the query's leading
// comment. A worker thread picks up new variables between two of its loops, so c's own thread is
// waited for: a marker comment shows up in the digest once it digests with comments kept.
static bool withKeptComments(PGconn* c, const std::function<bool()>& fn) {
	const char* var = "pgsql-query_digests_keep_comment";
	const std::string prev = scalar(g_admin,
		std::string("SELECT variable_value FROM global_variables WHERE variable_name='") + var + "'");
	const std::string marker = "hold_kc_" + g_mode + "_" + std::to_string(getpid());
	const bool set = setVar(g_admin, var, "true");
	bool kept = false;
	for (int i = 0; set && kept == false && i < 50; i++) {
		scalar(c, "SELECT /*" + marker + "*/ 1");
		const std::string n = scalar(g_admin,
			"SELECT COUNT(*) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + marker + "%'");
		kept = !n.empty() && n != "0";
		if (!kept) usleep(100000);
	}
	if (!kept) diag("digests never kept the marker comment");
	const bool good = kept && fn();
	setVar(g_admin, var, prev.empty() ? "false" : prev);
	return good;
}

struct Spelling {
	const char* name;
	std::function<bool(PGconn*)> declare;
	const char* fetch;   // FETCH 2 from the declared cursor
};

static const std::vector<Spelling> spellings() {
	const std::string series = SERIES;
	return {
		{ "BEGIN / DECLARE / COMMIT", [=](PGconn* c) {
			return execSQL(c, "BEGIN") && execSQL(c, "DECLARE c1 CURSOR WITH HOLD FOR " + series) && execSQL(c, "COMMIT");
		}, "FETCH 2 FROM c1" },
		{ "one multi-statement query", [=](PGconn* c) {
			return execSQL(c, "BEGIN; DECLARE c2 CURSOR WITH HOLD FOR " + series + "; COMMIT");
		}, "FETCH 2 FROM c2" },
		{ "lowercase, newlines and tabs", [=](PGconn* c) {
			return execSQL(c, "begin") &&
			       execSQL(c, "declare c3\n  cursor\n\twith   hold   for select g from generate_series(1,6) g") &&
			       execSQL(c, "commit");
		}, "FETCH 2 FROM c3" },
		{ "comment before DECLARE", [=](PGconn* c) {
			return execSQL(c, "BEGIN") && execSQL(c, "/* app */ DECLARE c4 CURSOR WITH HOLD FOR " + series) && execSQL(c, "COMMIT");
		}, "FETCH 2 FROM c4" },
		{ "comment before DECLARE, kept in the digest", [=](PGconn* c) {
			return withKeptComments(c, [&]() {
				return execSQL(c, "BEGIN") && execSQL(c, "/* app */ DECLARE c11 CURSOR WITH HOLD FOR " + series) &&
				       execSQL(c, "COMMIT");
			});
		}, "FETCH 2 FROM c11" },
		{ "INSENSITIVE SCROLL options", [=](PGconn* c) {
			return execSQL(c, "BEGIN") && execSQL(c, "DECLARE c5 INSENSITIVE SCROLL CURSOR WITH HOLD FOR " + series) && execSQL(c, "COMMIT");
		}, "FETCH 2 FROM c5" },
		{ "quoted cursor name", [=](PGconn* c) {
			return execSQL(c, "BEGIN") && execSQL(c, "DECLARE \"Hold Cursor\" CURSOR WITH HOLD FOR " + series) && execSQL(c, "COMMIT");
		}, "FETCH 2 FROM \"Hold Cursor\"" },
		{ "outside any transaction", [=](PGconn* c) {
			return execSQL(c, "DECLARE c7 CURSOR WITH HOLD FOR " + series);
		}, "FETCH 2 FROM c7" },
		{ "extended protocol, inside BEGIN", [=](PGconn* c) {
			return execSQL(c, "BEGIN") &&
			       execParams(c, "DECLARE c8 CURSOR WITH HOLD FOR SELECT g FROM generate_series(1,$1::int) g", "6") &&
			       execSQL(c, "COMMIT");
		}, "FETCH 2 FROM c8" },
		{ "extended protocol, named statement", [=](PGconn* c) {
			if (!execSQL(c, "BEGIN")) return false;
			PGresult* res = PQprepare(c, "dh", "DECLARE c9 CURSOR WITH HOLD FOR SELECT g FROM generate_series(1,$1::int) g", 1, nullptr);
			bool good = PQresultStatus(res) == PGRES_COMMAND_OK;
			PQclear(res);
			const char* param = "6";
			res = PQexecPrepared(c, "dh", 1, &param, nullptr, nullptr, 0);
			good = good && PQresultStatus(res) == PGRES_COMMAND_OK;
			if (!good) diag("prepared DECLARE failed: %s", PQerrorMessage(c));
			PQclear(res);
			return good && execSQL(c, "COMMIT");
		}, "FETCH 2 FROM c9" },
		{ "extended protocol, outside any transaction", [=](PGconn* c) {
			return execParams(c, "DECLARE c10 CURSOR WITH HOLD FOR SELECT g FROM generate_series(1,$1::int) g", "6");
		}, "FETCH 2 FROM c10" },
	};
}

// 4 assertions. The owner keeps the connection; another client neither shares it nor reads the
// cursor; the owner's position is untouched by the other client.
static void scenario_spelling(const Spelling& s) {
	const std::string tag = g_mode + " / " + s.name;
	const std::string cursor = std::string(s.fetch).substr(sizeof("FETCH 2 FROM ") - 1);
	if (!flushBackendPool(g_admin, g_servers)) {
		for (int i = 0; i < 4; i++) ok(false, "%s: pool flush failed", tag.c_str());
		return;
	}
	PGConnPtr owner = open_client_conn();
	if (PQstatus(owner.get()) != CONNECTION_OK || !s.declare(owner.get())) {
		for (int i = 0; i < 4; i++) ok(false, "%s: declaring the cursor failed", tag.c_str());
		return;
	}
	const long used = waitConnUsed(g_admin, 0, 500);
	ok(used == 1, "%s: the connection stays with the owner after the cursor is declared (ConnUsed=%ld)", tag.c_str(), used);

	const std::string first = rows_csv(owner.get(), s.fetch);
	const int owner_pid = backendPid(owner.get());

	PGConnPtr other = open_client_conn();
	const int other_pid = backendPid(other.get());
	ok(owner_pid > 0 && other_pid > 0 && other_pid != owner_pid,
	   "%s: another client is given a different backend (owner pid %d, other pid %d)", tag.c_str(), owner_pid, other_pid);
	const std::string stolen = rows_csv(other.get(), "FETCH 2 FROM " + cursor);
	ok(stolen == "<error>", "%s: another client cannot FETCH from the cursor (got '%s')", tag.c_str(), stolen.c_str());
	other.reset();

	const std::string second = rows_csv(owner.get(), s.fetch);
	ok(first == "1,2" && second == "3,4",
	   "%s: the owner reads its rows in order (first '%s', then '%s')", tag.c_str(), first.c_str(), second.c_str());
}

// 1 assertion each: cursors that end with their transaction do not hold the connection.
static void scenario_not_pinned(const char* name, const std::vector<std::string>& stmts, bool expect_failure) {
	const std::string tag = g_mode + " / " + name;
	if (!flushBackendPool(g_admin, g_servers)) {
		ok(false, "%s: pool flush failed", tag.c_str());
		return;
	}
	PGConnPtr c = open_client_conn();
	bool good = true;
	for (const auto& q : stmts) {
		PGresult* res = PQexec(c.get(), q.c_str());
		const ExecStatusType st = PQresultStatus(res);
		const bool failed = st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK;
		PQclear(res);
		if (failed && !(expect_failure && q.rfind("DECLARE", 0) == 0)) good = false;
	}
	const long used = waitConnUsed(g_admin, 0, 3000);
	ok(good && used == 0, "%s: the connection goes back to the pool (ConnUsed=%ld)", tag.c_str(), used);
}

// 1 assertion: the statement that drops every cursor lets the connection go.
static void scenario_released_by(const char* stmt) {
	const std::string tag = g_mode + " / " + stmt;
	if (!flushBackendPool(g_admin, g_servers)) {
		ok(false, "%s: pool flush failed", tag.c_str());
		return;
	}
	PGConnPtr c = open_client_conn();
	const bool good = execSQL(c.get(), "BEGIN") &&
		execSQL(c.get(), std::string("DECLARE r1 CURSOR WITH HOLD FOR ") + SERIES) &&
		execSQL(c.get(), "COMMIT") && execSQL(c.get(), stmt);
	const long used = waitConnUsed(g_admin, 0, 3000);
	ok(good && used == 0, "%s: releases the connection (ConnUsed=%ld)", tag.c_str(), used);
}

// 3 assertions. Closing one of two cursors leaves the other open, so the connection must stay
// held: individual cursors are not tracked.
static void scenario_close_one_of_two() {
	const std::string tag = g_mode + " / CLOSE one of two cursors";
	if (!flushBackendPool(g_admin, g_servers)) {
		for (int i = 0; i < 3; i++) ok(false, "%s: pool flush failed", tag.c_str());
		return;
	}
	PGConnPtr owner = open_client_conn();
	const bool good = execSQL(owner.get(), "BEGIN") &&
		execSQL(owner.get(), std::string("DECLARE k1 CURSOR WITH HOLD FOR ") + SERIES) &&
		execSQL(owner.get(), std::string("DECLARE k2 CURSOR WITH HOLD FOR ") + SERIES) &&
		execSQL(owner.get(), "COMMIT") && execSQL(owner.get(), "CLOSE k1");
	long used = waitConnUsed(g_admin, 0, 500);
	ok(good && used == 1, "%s: the connection stays held while k2 is open (ConnUsed=%ld)", tag.c_str(), used);

	PGConnPtr other = open_client_conn();
	const std::string stolen = rows_csv(other.get(), "FETCH 2 FROM k2");
	ok(stolen == "<error>", "%s: another client cannot FETCH from k2 (got '%s')", tag.c_str(), stolen.c_str());
	other.reset();

	execSQL(owner.get(), "CLOSE ALL");
	used = waitConnUsed(g_admin, 0, 3000);
	ok(used == 0, "%s: CLOSE ALL then releases it (ConnUsed=%ld)", tag.c_str(), used);
}

// 3 assertions. The owner leaves with its cursor open; the connection is reset and pooled, and
// the next client, handed that very backend, finds no cursor.
static void scenario_owner_disconnects() {
	const std::string tag = g_mode + " / owner disconnects";
	if (!flushBackendPool(g_admin, g_servers)) {
		for (int i = 0; i < 3; i++) ok(false, "%s: pool flush failed", tag.c_str());
		return;
	}
	int owner_pid = -1;
	{
		PGConnPtr owner = open_client_conn();
		execSQL(owner.get(), "BEGIN");
		execSQL(owner.get(), std::string("DECLARE d1 CURSOR WITH HOLD FOR ") + SERIES);
		execSQL(owner.get(), "COMMIT");
		owner_pid = backendPid(owner.get());
	}
	waitConnUsed(g_admin, 0, 5000);
	const uint64_t deadline = now_ms() + 5000;
	while (poolSum(g_admin, "ConnFree") < 1 && now_ms() < deadline) usleep(50000);

	PGConnPtr next = open_client_conn();
	const int next_pid = backendPid(next.get());
	ok(owner_pid > 0 && next_pid == owner_pid,
	   "%s: the next client is handed the same backend (pid %d -> %d)", tag.c_str(), owner_pid, next_pid);
	const std::string stolen = rows_csv(next.get(), "FETCH 2 FROM d1");
	ok(stolen == "<error>", "%s: and cannot FETCH from the owner's cursor (got '%s')", tag.c_str(), stolen.c_str());
	const bool redeclared = execSQL(next.get(), "BEGIN") &&
		execSQL(next.get(), std::string("DECLARE d1 CURSOR WITH HOLD FOR ") + SERIES) &&
		execSQL(next.get(), "COMMIT") && execSQL(next.get(), "CLOSE ALL");
	ok(redeclared, "%s: and can declare a cursor of the same name", tag.c_str());
}

// 3 assertions. Two clients use the same cursor name at once, each reading its own rows.
static void scenario_same_name() {
	const std::string tag = g_mode + " / same cursor name in two clients";
	if (!flushBackendPool(g_admin, g_servers)) {
		for (int i = 0; i < 3; i++) ok(false, "%s: pool flush failed", tag.c_str());
		return;
	}
	PGConnPtr a = open_client_conn();
	PGConnPtr b = open_client_conn();
	execSQL(a.get(), "BEGIN");
	execSQL(a.get(), "DECLARE s CURSOR WITH HOLD FOR SELECT 'a-' || g FROM generate_series(1,6) g");
	execSQL(a.get(), "COMMIT");
	const bool b_declared = execSQL(b.get(), "BEGIN") &&
		execSQL(b.get(), "DECLARE s CURSOR WITH HOLD FOR SELECT 'b-' || g FROM generate_series(1,6) g") &&
		execSQL(b.get(), "COMMIT");
	ok(b_declared, "%s: the second client declares its cursor without a name clash", tag.c_str());
	const std::string ra = rows_csv(a.get(), "FETCH 2 FROM s");
	const std::string rb = rows_csv(b.get(), "FETCH 2 FROM s");
	ok(ra == "a-1,a-2", "%s: the first client reads its own rows (got '%s')", tag.c_str(), ra.c_str());
	ok(rb == "b-1,b-2", "%s: the second client reads its own rows (got '%s')", tag.c_str(), rb.c_str());
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	const size_t n_spellings = spellings().size();
	plan(2 * (4 * n_spellings + 3 + 3 + 3 + 3 + 3));

	PGConnPtr admin = open_admin_conn();
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connect failed: %s", PQerrorMessage(admin.get()));
		return exit_status();
	}
	g_admin = admin.get();
	g_servers = readServers(g_admin, BACKEND_HG);
	const std::string orig_native = scalar(g_admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::string orig_multiplexing = scalar(g_admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-multiplexing'");
	setVar(g_admin, "pgsql-multiplexing", "true");

	for (const char* native : { "true", "false" }) {
		g_mode = std::string(native) == "true" ? "native" : "libpq";
		setVar(g_admin, "pgsql-use_native_backend_protocol", native);

		for (const auto& s : spellings()) scenario_spelling(s);

		scenario_not_pinned("WITHOUT HOLD", { "BEGIN", std::string("DECLARE n1 CURSOR WITHOUT HOLD FOR ") + SERIES, "COMMIT" }, false);
		scenario_not_pinned("no HOLD clause", { "BEGIN", std::string("DECLARE n2 CURSOR FOR ") + SERIES, "COMMIT" }, false);
		scenario_not_pinned("failed DECLARE ... WITH HOLD",
			{ "BEGIN", "DECLARE n3 CURSOR WITH HOLD FOR SELECT * FROM no_such_table_hold_cursor", "ROLLBACK" }, true);

		scenario_released_by("CLOSE ALL");
		scenario_released_by("close all");
		scenario_released_by("DISCARD ALL");

		scenario_close_one_of_two();
		scenario_owner_disconnects();
		scenario_same_name();
	}

	if (!orig_native.empty()) setVar(g_admin, "pgsql-use_native_backend_protocol", orig_native);
	if (!orig_multiplexing.empty()) setVar(g_admin, "pgsql-multiplexing", orig_multiplexing);
	flushBackendPool(g_admin, g_servers);
	return exit_status();
}
