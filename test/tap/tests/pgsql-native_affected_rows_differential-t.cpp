/**
 * @file pgsql-native_affected_rows_differential-t.cpp
 * @brief Affected rows of a multi-statement simple query: native backend vs libpq (#6435).
 *
 * A native simple query feeds every statement of a batch into one result up to
 * ReadyForQuery. The "this CommandComplete closes a row-returning statement" test
 * used to read the result-wide TUPLE flag, so once a SELECT had run, the count of
 * every later DML in the same batch was dropped:
 *   SELECT 1; UPDATE t                      -> native recorded nothing (libpq: 10)
 *   UPDATE (5 rows); SELECT 1; UPDATE (3)   -> native recorded 5       (libpq: 3)
 * The client bytes were always right; what went wrong is what ProxySQL records:
 * stats_pgsql_query_digest.sum_rows_affected and the events log.
 *
 * For each backend mode -- libpq first as the oracle, then native -- the pool is
 * emptied (a backend connection is built libpq or native once and never converts),
 * the digest stats and the in-memory events log are reset, and three batches run
 * on a new client connection. Every batch must record the libpq count (the last
 * DML count of the batch wins) in both places, and native must equal libpq. The
 * client's pooled connection is then checked to be of the mode under test, so a
 * phase served by the wrong kind of connection fails instead of passing vacuously.
 *
 * Runtime state (backend mode, eventslog settings, servers) is restored at the
 * end, never saved to disk.
 */
#include <chrono>
#include <cstdlib>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "libpq-fe.h"
#include "json.hpp"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using nlohmann::json;
CommandLine cl;

static PGConnPtr openConn(const char* host, int port, const char* user,
                          const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable connect_timeout=10";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createAdminConn() {
	return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
	                cl.admin_username, cl.admin_password, nullptr);
}

static PGConnPtr createClientConn() {
	return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username,
	                cl.pgsql_password, cl.pgsql_username);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
	PGresult* r = PQexec(admin, q.c_str());
	const ExecStatusType st = PQresultStatus(r);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
	PQclear(r);
	return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		v = PQgetvalue(r, 0, 0);
	PQclear(r);
	return v;
}

// Runs a (possibly multi-statement) simple query and drains every result.
// True when no statement failed.
static bool execClient(PGconn* c, const std::string& q) {
	if (!PQsendQuery(c, q.c_str())) {
		diag("client send failed: %s -- %s", q.c_str(), PQerrorMessage(c));
		return false;
	}
	bool good = true;
	PGresult* r;
	while ((r = PQgetResult(c)) != nullptr) {
		const ExecStatusType st = PQresultStatus(r);
		if (st != PGRES_COMMAND_OK && st != PGRES_TUPLES_OK) {
			diag("client failed: %s -- %s", q.c_str(), PQresultErrorMessage(r));
			good = false;
		}
		PQclear(r);
	}
	return good;
}

template <typename Predicate>
static bool waitUntil(Predicate predicate, int timeout_ms) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	do {
		if (predicate()) return true;
		usleep(50 * 1000);
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

static bool setNativeMode(PGconn* admin, bool enabled) {
	return execAdmin(admin, std::string("SET pgsql-use_native_backend_protocol='") +
	                        (enabled ? "true" : "false") + "'") &&
	       execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static const char* SERVER_COLS =
	"hostgroup_id,hostname,port,status,weight,compression,max_connections,"
	"max_replication_lag,use_ssl,max_latency_ms,comment";

static std::string sqlQuote(const std::string& v) {
	std::string out = "'";
	for (char c : v) { if (c == '\'') out += "''"; else out += c; }
	return out + "'";
}

// The hostgroup's servers as the INSERTs that recreate them, every column included.
static std::vector<std::string> snapshotServers(PGconn* admin, int hg) {
	std::vector<std::string> inserts;
	std::stringstream sel;
	sel << "SELECT " << SERVER_COLS << " FROM pgsql_servers WHERE hostgroup_id=" << hg;
	PGresult* res = PQexec(admin, sel.str().c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		const int rows = PQntuples(res), cols = PQnfields(res);
		for (int r = 0; r < rows; r++) {
			std::stringstream ins;
			ins << "INSERT INTO pgsql_servers (" << SERVER_COLS << ") VALUES (";
			for (int c = 0; c < cols; c++) {
				if (c) ins << ",";
				if (PQgetisnull(res, r, c)) ins << "NULL";
				else ins << sqlQuote(PQgetvalue(res, r, c));
			}
			ins << ")";
			inserts.push_back(ins.str());
		}
	} else {
		diag("snapshotServers: %s", PQerrorMessage(admin));
	}
	PQclear(res);
	return inserts;
}

static bool restoreServers(PGconn* admin, int hg, const std::vector<std::string>& inserts) {
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	for (const auto& q : inserts) {
		if (!execAdmin(admin, q)) return false;
	}
	return execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

static int poolCount(PGconn* admin, int hg, const char* col) {
	const std::string v = scalar(admin, std::string("SELECT COALESCE(SUM(") + col +
		"),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + std::to_string(hg));
	return v.empty() ? -1 : atoi(v.c_str());
}

// Removing the servers closes their free connections; OFFLINE_HARD does not.
// Connections still in use survive the removal and return to the pool afterwards,
// still built in whatever mode a previous test left behind. So wait for the
// hostgroup to have none in use first, and check the pool really is empty after.
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<std::string>& inserts) {
	if (inserts.empty()) return false;
	for (int attempt = 0; attempt < 3; attempt++) {
		if (!waitUntil([&]() { return poolCount(admin, hg, "ConnUsed") == 0; }, 10000))
			diag("flushBackendPool: hostgroup %d still has connections in use", hg);
		if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
		if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
		if (!restoreServers(admin, hg, inserts)) return false;
		usleep(200000);
		const int used = poolCount(admin, hg, "ConnUsed"), free_ = poolCount(admin, hg, "ConnFree");
		if (used == 0 && free_ == 0) return true;
		diag("flushBackendPool: attempt %d left ConnUsed=%d ConnFree=%d", attempt, used, free_);
	}
	return false;
}

// The real backend pid: a bare SELECT pg_backend_pid() is answered by ProxySQL.
static std::string backendPid(PGconn* c) {
	return scalar(c, "SELECT pid FROM pg_stat_activity WHERE pid = pg_backend_pid()");
}

// pgsql_info of the pooled connection with this backend pid, or null when not pooled.
static json pooledInfo(PGconn* admin, const std::string& pid) {
	PGresult* r = PQexec(admin, "SELECT pgsql_info FROM stats_pgsql_free_connections");
	json found;
	if (PQresultStatus(r) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(r) && found.is_null(); i++) {
			if (PQgetisnull(r, i, 0)) continue;
			const json j = json::parse(PQgetvalue(r, i, 0), nullptr, false);
			if (j.is_object() && j.contains("backend_pid") && j["backend_pid"].is_number() &&
			    std::to_string(j["backend_pid"].get<long long>()) == pid) {
				found = j;
			}
		}
	}
	PQclear(r);
	return found;
}

// One multi-statement simple query. The alias names the batch in the digest text
// and in the events log; libpq_rows is what libpq records (last DML count wins).
struct Batch {
	std::string alias;
	std::string sql;
	long long libpq_rows;
};

static std::vector<Batch> makeBatches(const std::string& t) {
	return {
		// The issue's case: the DML after a row-returning statement was dropped.
		{ "b6435a", "SELECT 1 AS b6435a; UPDATE " + t + " SET x=x+1", 10 },
		// The first DML count was kept instead of the last.
		{ "b6435b", "UPDATE " + t + " SET x=x+1 WHERE id<=5; SELECT 1 AS b6435b; "
		                       "UPDATE " + t + " SET x=x+1 WHERE id<=3", 3 },
		// Control: a DML before the SELECT was always recorded.
		{ "b6435c", "UPDATE " + t + " SET x=x+1 WHERE id<=4; SELECT 1 AS b6435c", 4 },
	};
}

static long long digestRowsAffected(PGconn* admin, const std::string& alias) {
	const std::string v = scalar(admin, "SELECT SUM(sum_rows_affected) FROM stats_pgsql_query_digest "
		"WHERE digest_text LIKE '%" + alias + "%'");
	return v.empty() ? -1 : atoll(v.c_str());
}

static long long eventRowsAffected(PGconn* admin, const std::string& alias) {
	const std::string v = scalar(admin, "SELECT affected_rows FROM stats_pgsql_query_events "
		"WHERE query LIKE '%" + alias + "%' ORDER BY id DESC LIMIT 1");
	return v.empty() ? -1 : atoll(v.c_str());
}

static const int TESTS_PER_PHASE = 1 + 1 + 3 * 2 + 1;

// alias -> {digest sum_rows_affected, events affected_rows}
using PhaseResult = std::map<std::string, std::pair<long long, long long>>;

static PhaseResult runPhase(PGconn* admin, int hg, const std::vector<std::string>& servers,
                            const std::vector<Batch>& batches, bool native) {
	PhaseResult res;
	const char* phase = native ? "native" : "libpq";
	const bool ready = setNativeMode(admin, native) && flushBackendPool(admin, hg, servers) &&
		execAdmin(admin, "SELECT * FROM stats_pgsql_query_digest_reset") &&
		execAdmin(admin, "DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY") &&
		execAdmin(admin, "DELETE FROM stats_pgsql_query_events");
	ok(ready, "%s: backend mode selected, pool of hostgroup %d emptied, stats reset", phase, hg);
	if (!ready) { skip(TESTS_PER_PHASE - 1, "%s: could not prepare the phase", phase); return res; }

	auto c = createClientConn();
	bool ran = PQstatus(c.get()) == CONNECTION_OK;
	if (!ran) diag("%s: client: %s", phase, PQerrorMessage(c.get()));
	// Holding a transaction pins the backend, so its pid names the connection that ran the batches.
	std::string pid;
	if (ran) ran = execClient(c.get(), "BEGIN") && !(pid = backendPid(c.get())).empty();
	for (const auto& b : batches) {
		if (ran) ran = execClient(c.get(), b.sql);
	}
	if (ran) ran = execClient(c.get(), "COMMIT");
	ok(ran, "%s: the three batches ran on backend pid %s", phase, pid.c_str());

	execAdmin(admin, "DUMP PGSQL EVENTSLOG FROM BUFFER TO MEMORY");
	for (const auto& b : batches) {
		const long long dg = digestRowsAffected(admin, b.alias);
		const long long ev = eventRowsAffected(admin, b.alias);
		res[b.alias] = { dg, ev };
		ok(dg == b.libpq_rows, "%s: %s: digest sum_rows_affected=%lld, expected %lld",
		   phase, b.alias.c_str(), dg, b.libpq_rows);
		ok(ev == b.libpq_rows, "%s: %s: events log affected_rows=%lld, expected %lld",
		   phase, b.alias.c_str(), ev, b.libpq_rows);
	}

	// The connection back in the pool: it must be the mode under test.
	c.reset();
	json info;
	if (!pid.empty()) waitUntil([&]() { info = pooledInfo(admin, pid); return !info.is_null(); }, 3000);
	const bool is_native = info.is_object() && info.contains("native_mode") && info["native_mode"] == true;
	ok(!info.is_null() && is_native == native, "%s: pooled connection pid %s reports native_mode=%s",
	   phase, pid.c_str(), info.is_null() ? "(not pooled)" : (is_native ? "true" : "false"));
	return res;
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const std::string table = "t6435_" + std::to_string(getpid());
	const std::vector<Batch> batches = makeBatches(table);

	plan(1 + 2 * TESTS_PER_PHASE + (int)batches.size() + 1); // + restore

	auto admin = createAdminConn();
	if (PQstatus(admin.get()) != CONNECTION_OK) {
		BAIL_OUT("admin connection failed: %s", PQerrorMessage(admin.get()));
		return exit_status();
	}

	const std::string hg_s = scalar(admin.get(),
		std::string("SELECT default_hostgroup FROM runtime_pgsql_users WHERE username=") +
		sqlQuote(cl.pgsql_username) + " LIMIT 1");
	const std::string orig_native = scalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::string orig_history = scalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-eventslog_buffer_history_size'");
	const std::string orig_default_log = scalar(admin.get(),
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-eventslog_default_log'");
	if (hg_s.empty() || orig_native.empty() || orig_history.empty() || orig_default_log.empty()) {
		BAIL_OUT("cannot read default hostgroup ('%s') or the pgsql variables ('%s','%s','%s')",
		         hg_s.c_str(), orig_native.c_str(), orig_history.c_str(), orig_default_log.c_str());
		return exit_status();
	}
	const int hg = atoi(hg_s.c_str());
	const std::vector<std::string> servers = snapshotServers(admin.get(), hg);
	diag("hostgroup %d, %zu server(s), pgsql-use_native_backend_protocol originally '%s'",
	     hg, servers.size(), orig_native.c_str());

	// Every query goes to the in-memory events buffer.
	bool setup = execAdmin(admin.get(), "SET pgsql-eventslog_buffer_history_size=100000") &&
		execAdmin(admin.get(), "SET pgsql-eventslog_default_log=1") &&
		execAdmin(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	{
		auto c = createClientConn();
		setup = setup && PQstatus(c.get()) == CONNECTION_OK &&
			execClient(c.get(), "DROP TABLE IF EXISTS " + table) &&
			execClient(c.get(), "CREATE TABLE " + table + " (id INT PRIMARY KEY, x INT NOT NULL DEFAULT 0)") &&
			execClient(c.get(), "INSERT INTO " + table + " (id) SELECT generate_series(1, 10)");
		if (PQstatus(c.get()) != CONNECTION_OK) diag("client: %s", PQerrorMessage(c.get()));
	}
	ok(setup, "events log enabled, table %s created with 10 rows", table.c_str());

	PhaseResult libpq, native;
	if (setup) {
		libpq = runPhase(admin.get(), hg, servers, batches, false);
		native = runPhase(admin.get(), hg, servers, batches, true);
	} else {
		skip(2 * TESTS_PER_PHASE, "setup failed");
	}
	for (const auto& b : batches) {
		const auto& l = libpq[b.alias];
		const auto& n = native[b.alias];
		ok(setup && l == n, "%s: native records what libpq records (digest %lld/%lld, events %lld/%lld)",
		   b.alias.c_str(), n.first, l.first, n.second, l.second);
	}

	// Restore the original runtime state, with a pool built under the original mode.
	// A failed restore leaves shared ProxySQL state changed for later tests: fail on it.
	const bool vars_restored =
		execAdmin(admin.get(), "SET pgsql-use_native_backend_protocol='" + orig_native + "'") &&
		execAdmin(admin.get(), "SET pgsql-eventslog_buffer_history_size='" + orig_history + "'") &&
		execAdmin(admin.get(), "SET pgsql-eventslog_default_log='" + orig_default_log + "'") &&
		execAdmin(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
	// The pool must also be emptied, so that no connection built in the other mode is left
	// behind. A failed flush can have stopped before the rows were back: put them back and
	// flush once more, and only an emptied pool counts as restored.
	bool servers_restored = servers.empty() || flushBackendPool(admin.get(), hg, servers);
	if (!servers_restored) {
		diag("restore: hostgroup %d pool not emptied, restoring its servers and flushing again", hg);
		servers_restored = restoreServers(admin.get(), hg, servers) && flushBackendPool(admin.get(), hg, servers);
	}
	ok(vars_restored && servers_restored, "original pgsql variables and hostgroup %d servers restored "
	   "(variables %s, servers %s)", hg, vars_restored ? "ok" : "FAILED", servers_restored ? "ok" : "FAILED");
	{
		auto c = createClientConn();
		if (PQstatus(c.get()) == CONNECTION_OK) execClient(c.get(), "DROP TABLE IF EXISTS " + table);
	}

	return exit_status();
}
