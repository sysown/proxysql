/**
 * @file pgsql-native_extq_copy_in_sync-t.cpp
 * @brief An extended-query COPY ... FROM STDIN that reaches the native drive must end
 *        with an error and leave the session usable, not hang.
 *
 * WHY THIS EXISTS
 * ---------------
 * COPY ... FROM STDIN is normally recognized by the session and handed to fast_forward.
 * The detector is a regex that does not cross a ';', so a ';' inside a quoted identifier
 * hides the statement from it: `COPY "a;b" FROM STDIN` reaches the native backend drive.
 * The drive cannot supply CopyData, so it answers the CopyInResponse with a CopyFail.
 *
 * For a simple Query that is enough. For Parse/Bind/Execute/Sync it was not:
 *  - PostgreSQL ignores Sync while in copy-in mode, so the Sync that followed the
 *    Execute is consumed before the CopyFail arrives;
 *  - the CopyFail raises an error during an extended-query message, so the backend
 *    then discards everything until the next Sync, and sends no ReadyForQuery;
 *  - ProxySQL waited for that ReadyForQuery. Client session and backend connection
 *    stayed stuck until the client went away. A query timeout did not help, because
 *    the CancelRequest finds the backend idle, waiting for input.
 * The drive now sends a Sync right behind the CopyFail on a Sync-terminated extended
 * step, which yields exactly one ReadyForQuery.
 *
 * WHAT IT CHECKS (native backend protocol only; skipped where it does not exist)
 *  - unnamed statement (PQsendQueryParams: Parse/Bind/Describe/Execute/Sync);
 *  - named statement (PQsendPrepare, then PQsendQueryPrepared);
 *  - the unnamed case inside BEGIN, where ReadyForQuery must report the failed block.
 * Each case must return SQLSTATE 57014 (CopyFail) within a few seconds, with the
 * correct transaction status, and the same client connection must then answer
 * SELECT 1. Without the fix every case times out. A log check confirms the statement
 * really reached the native drive rather than fast_forward.
 *
 * INFRA: legacy-g1. Runtime state restored in memory only -- never SAVE ... TO DISK.
 */
#include <chrono>
#include <cstring>
#include <fstream>
#include <memory>
#include <poll.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int BACKEND_HG = 0;
// Generous for a statement that fails at once; before the fix it never returns.
static const int RESULT_TIMEOUT_MS = 5000;
static const int N_CASES = 3;
static const int ASSERTS_PER_CASE = 3;

static PGConnPtr createAdminConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password
	   << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createClientConn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static bool execAdmin(PGconn* admin, const std::string& q) {
	PGresult* r = PQexec(admin, q.c_str());
	ExecStatusType st = PQresultStatus(r);
	bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
	PQclear(r);
	return good;
}

static std::string adminScalar(PGconn* admin, const std::string& q) {
	PGresult* r = PQexec(admin, q.c_str());
	std::string v;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		v = PQgetvalue(r, 0, 0);
	PQclear(r);
	return v;
}

static bool setNativeMode(PGconn* admin, bool on) {
	return execAdmin(admin, std::string("SET pgsql-use_native_backend_protocol='") +
	                        (on ? "true" : "false") + "'") &&
	       execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// A pooled backend connection keeps the protocol it was opened with. Re-inserting the
// server rows drops the pool, so the cases below run on native connections. The rows
// are kept as INSERTs recreating every column, quotes doubled.
static std::vector<std::string> readServers(PGconn* admin, int hg) {
	std::vector<std::string> rows;
	PGresult* res = PQexec(admin, ("SELECT * FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg)).c_str());
	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		std::string cols;
		for (int c = 0; c < PQnfields(res); c++) cols += std::string(c ? "," : "") + PQfname(res, c);
		for (int i = 0; i < PQntuples(res); i++) {
			std::string ins = "INSERT INTO pgsql_servers (" + cols + ") VALUES (";
			for (int c = 0; c < PQnfields(res); c++) {
				if (c) ins += ",";
				if (PQgetisnull(res, i, c)) { ins += "NULL"; continue; }
				ins += "'";
				for (const char* v = PQgetvalue(res, i, c); *v; v++) ins += (*v == '\'') ? "''" : std::string(1, *v);
				ins += "'";
			}
			rows.push_back(ins + ")");
		}
	} else {
		diag("readServers failed: %s", PQerrorMessage(admin));
	}
	PQclear(res);
	return rows;
}

static bool flushBackendPool(PGconn* admin, int hg, const std::vector<std::string>& saved) {
	if (saved.empty()) return false;
	if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg))) return false;
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& ins : saved) {
		if (!execAdmin(admin, ins)) return false;
	}
	if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

// Outcome of one command sent with a PQsend* call.
struct Outcome {
	bool timed_out = false;
	ExecStatusType status = PGRES_EMPTY_QUERY;  // of the first error result, else of the last result
	std::string sqlstate;
	std::string message;
	std::string value;                           // first cell of the last tuples result
};

// Collect every result of the command in flight, never blocking past the deadline.
// PQgetResult() blocks while PQisBusy(), so the socket is polled first: a backend
// that never sends ReadyForQuery shows up as a timeout instead of a hung test.
static Outcome waitResults(PGconn* c, int timeout_ms) {
	Outcome o;
	bool have_error = false;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	for (;;) {
		while (PQisBusy(c)) {
			const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
				deadline - std::chrono::steady_clock::now()).count();
			if (left <= 0) { o.timed_out = true; return o; }
			struct pollfd pfd = { PQsocket(c), POLLIN, 0 };
			if (poll(&pfd, 1, (int)left) < 0 || PQconsumeInput(c) == 0) {
				o.message = PQerrorMessage(c);
				o.status = PGRES_FATAL_ERROR;
				return o;
			}
		}
		PGresult* r = PQgetResult(c);
		if (r == nullptr) break;
		const ExecStatusType st = PQresultStatus(r);
		if (st == PGRES_FATAL_ERROR && !have_error) {
			have_error = true;
			o.status = st;
			const char* ss = PQresultErrorField(r, PG_DIAG_SQLSTATE);
			o.sqlstate = ss ? ss : "";
			o.message = PQresultErrorMessage(r);
		} else if (!have_error) {
			o.status = st;
			if (st == PGRES_TUPLES_OK && PQntuples(r) > 0) o.value = PQgetvalue(r, 0, 0);
		}
		PQclear(r);
		if (st == PGRES_COPY_IN || st == PGRES_COPY_OUT) {
			// Must never happen: the client is not supposed to enter COPY mode.
			o.message = "client was put in COPY mode";
			o.status = st;
			return o;
		}
	}
	return o;
}

static Outcome simple(PGconn* c, const std::string& q) {
	if (!PQsendQuery(c, q.c_str())) {
		Outcome o; o.status = PGRES_FATAL_ERROR; o.message = PQerrorMessage(c); return o;
	}
	return waitResults(c, RESULT_TIMEOUT_MS);
}

enum class Shape { UNNAMED, NAMED, UNNAMED_IN_TXN };

static const char* shapeName(Shape s) {
	switch (s) {
		case Shape::UNNAMED: return "unnamed Parse/Bind/Execute/Sync";
		case Shape::NAMED: return "named prepared statement";
		default: return "unnamed, inside BEGIN";
	}
}

static void runCase(Shape shape, const std::string& copy_sql) {
	const char* name = shapeName(shape);
	PGConnPtr conn = createClientConn();
	if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
		diag("[%s] client connect failed: %s", name, conn ? PQerrorMessage(conn.get()) : "null");
		for (int i = 0; i < ASSERTS_PER_CASE; i++) ok(false, "[%s] client connection", name);
		return;
	}
	PGconn* c = conn.get();

	const bool in_txn = (shape == Shape::UNNAMED_IN_TXN);
	if (in_txn) {
		Outcome b = simple(c, "BEGIN");
		if (b.timed_out || b.status != PGRES_COMMAND_OK) diag("[%s] BEGIN failed: %s", name, b.message.c_str());
	}

	int sent = 0;
	if (shape == Shape::NAMED) {
		if (PQsendPrepare(c, "n_copy_in_sync", copy_sql.c_str(), 0, nullptr)) {
			Outcome p = waitResults(c, RESULT_TIMEOUT_MS);
			if (p.timed_out || p.status != PGRES_COMMAND_OK)
				diag("[%s] Parse failed: %s", name, p.timed_out ? "timeout" : p.message.c_str());
		}
		sent = PQsendQueryPrepared(c, "n_copy_in_sync", 0, nullptr, nullptr, nullptr, 0);
	} else {
		sent = PQsendQueryParams(c, copy_sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
	}
	if (!sent) diag("[%s] send failed: %s", name, PQerrorMessage(c));

	const auto t0 = std::chrono::steady_clock::now();
	Outcome copy = sent ? waitResults(c, RESULT_TIMEOUT_MS) : Outcome{};
	const long long ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - t0).count();
	diag("[%s] COPY outcome after %lld ms: timed_out=%d status=%s sqlstate='%s' msg='%s'",
	     name, ms, copy.timed_out, PQresStatus(copy.status), copy.sqlstate.c_str(), copy.message.c_str());
	ok(sent && !copy.timed_out && copy.status == PGRES_FATAL_ERROR && copy.sqlstate == "57014",
	   "[%s] COPY FROM STDIN fails with SQLSTATE 57014 within %d ms (got '%s'%s)",
	   name, RESULT_TIMEOUT_MS, copy.sqlstate.c_str(), copy.timed_out ? ", timed out" : "");

	if (copy.timed_out) {
		// The connection is wedged; nothing more can be learned from it.
		ok(false, "[%s] transaction status after the error (connection hung)", name);
		ok(false, "[%s] same connection answers SELECT 1 (connection hung)", name);
		return;
	}

	const PGTransactionStatusType ts = PQtransactionStatus(c);
	const PGTransactionStatusType want = in_txn ? PQTRANS_INERROR : PQTRANS_IDLE;
	ok(ts == want, "[%s] transaction status after the error is %s (got %d)",
	   name, in_txn ? "INERROR" : "IDLE", (int)ts);

	if (in_txn) {
		Outcome rb = simple(c, "ROLLBACK");
		if (rb.timed_out || rb.status != PGRES_COMMAND_OK) diag("[%s] ROLLBACK failed: %s", name, rb.message.c_str());
	}
	Outcome sel = simple(c, "SELECT 1");
	ok(!sel.timed_out && sel.status == PGRES_TUPLES_OK && sel.value == "1",
	   "[%s] same connection answers SELECT 1 afterwards (status=%s%s)",
	   name, PQresStatus(sel.status), sel.timed_out ? ", timed out" : "");
}

int main(int, char**) {
	plan(N_CASES * ASSERTS_PER_CASE + 1);
	if (cl.getEnv()) return exit_status();

	PGConnPtr adminOwner = createAdminConn();
	if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
		BAIL_OUT("cannot proceed without an admin connection");
	PGconn* admin = adminOwner.get();

	if (!pgsql_native_supported(admin)) {
		skip(N_CASES * ASSERTS_PER_CASE + 1, "native backend protocol is unavailable in this tier");
		return exit_status();
	}

	std::fstream f_log;
	const std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
	if (open_file_and_seek_end(log_path, f_log) != EXIT_SUCCESS)
		BAIL_OUT("cannot open the ProxySQL log at %s", log_path.c_str());

	const std::string saved_native = adminScalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::vector<std::string> saved_servers = readServers(admin, BACKEND_HG);
	auto cleanup = [&]() {
		if (!saved_native.empty()) setNativeMode(admin, saved_native == "true" || saved_native == "1");
		flushBackendPool(admin, BACKEND_HG, saved_servers);
	};
	if (saved_servers.empty()) BAIL_OUT("no pgsql_servers rows for hostgroup %d", BACKEND_HG);
	if (!setNativeMode(admin, true) || !flushBackendPool(admin, BACKEND_HG, saved_servers)) {
		cleanup();
		BAIL_OUT("cannot switch to the native backend protocol");
	}

	// The ';' inside the quoted table name is what keeps the session's COPY detector
	// from seeing the statement. The table must exist, or the error comes from Bind
	// instead and COPY mode is never entered.
	const std::string table = "\"copy_in_sync;" + std::to_string(getpid()) + "\"";
	const std::string copy_sql = "COPY " + table + " FROM STDIN";
	{
		PGConnPtr c = createClientConn();
		if (!c || PQstatus(c.get()) != CONNECTION_OK) { cleanup(); BAIL_OUT("client connect failed"); }
		Outcome mk = simple(c.get(), "CREATE TABLE " + table + " (id int4)");
		if (mk.timed_out || mk.status != PGRES_COMMAND_OK) {
			cleanup();
			BAIL_OUT("cannot create the fixture table: %s", mk.message.c_str());
		}
	}

	runCase(Shape::UNNAMED, copy_sql);
	runCase(Shape::NAMED, copy_sql);
	runCase(Shape::UNNAMED_IN_TXN, copy_sql);

	ok(wait_for_log_match(f_log, ".*unexpected CopyInResponse/CopyBothResponse.*", 2000, 100),
	   "the COPY reached the native backend drive (not fast_forward)");

	{
		PGConnPtr c = createClientConn();
		if (c && PQstatus(c.get()) == CONNECTION_OK) simple(c.get(), "DROP TABLE IF EXISTS " + table);
	}
	cleanup();
	return exit_status();
}
