/**
 * @file pgsql-tx_poisoned_extended_query-t.cpp
 * @brief Extended-query coverage for the tx_poisoned recovery feature.
 *
 * Sibling to pgsql-tx_poisoned_recovery-t (which exercises Simple Query). This
 * test walks the PostgreSQL extended-query protocol through libpq's high-level
 * wrappers (PQexecParams, PQprepare, PQexecPrepared) and asserts:
 *
 *   * While tx_poisoned, every extended-query round trip lands as
 *     ErrorResponse(severity=ERROR, SQLSTATE=25P02) at Sync — NOT FATAL, NOT
 *     57P01.
 *   * pgsql_tx_poisoned_rejected_statements_total increments by EXACTLY 3
 *     (one per logical ext-query call, regardless of the 4–6 Parse/Bind/
 *     Describe/Execute/Sync wire packets each call sends). This is the
 *     mechanical proof that per-statement accounting is in effect.
 *   * A Simple-Query ROLLBACK still recovers the session.
 *   * Post-recovery, both PQexecParams and PQprepare+PQexecPrepared execute
 *     cleanly and return rows.
 *
 * Flake-resistance and admin-var hygiene match the sibling test: poll
 * pg_stat_activity for the marker backend (no fixed 500ms sleep), surface
 * kill-delivery failures as clear diag, restore the admin variable on scope
 * exit via RAII.
 */

#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static PGconn* open_conn(const char* host, int port,
                         const char* user, const char* password,
                         const char* label) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port;
	ss << " user=" << user << " password=" << password;
	ss << " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("Connection to %s (%s:%d user=%s) failed: %s",
		     label, host, port, user, PQerrorMessage(c));
		PQfinish(c);
		return nullptr;
	}
	return c;
}

static bool set_admin_bool(const char* var, bool value) {
	PGconn* admin = open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port,
	                          cl.admin_username, cl.admin_password,
	                          "ProxySQL admin (PgSQL protocol)");
	if (!admin) return false;
	// Admin stores PgSQL admin vars with the 'pgsql-' prefix in
	// variable_name. Without the prefix, UPDATE affects 0 rows silently.
	char q[256];
	snprintf(q, sizeof(q),
	         "UPDATE global_variables SET variable_value='%s' WHERE variable_name='pgsql-%s'",
	         value ? "true" : "false", var);
	PGresult* r = PQexec(admin, q);
	bool ok1 = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	r = PQexec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	bool ok2 = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	PQfinish(admin);
	// Warm all PgSQL workers so the __thread admin-var refresh has definitely
	// landed everywhere before the caller proceeds. See the detailed comment
	// in pgsql-tx_poisoned_recovery-t.cpp's set_admin_bool.
	for (int i = 0; i < 8; ++i) {
		PGconn* warm = PQconnectdb((std::string("host=") + cl.pgsql_host
			+ " port=" + std::to_string(cl.pgsql_port)
			+ " user=" + cl.pgsql_username
			+ " password=" + cl.pgsql_password
			+ " sslmode=disable connect_timeout=2").c_str());
		if (PQstatus(warm) == CONNECTION_OK) {
			PGresult* ping = PQexec(warm, "SELECT 1");
			PQclear(ping);
		}
		PQfinish(warm);
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	return ok1 && ok2;
}

struct RestorePreserveClientAdminVar {
	~RestorePreserveClientAdminVar() {
		set_admin_bool("preserve_client_on_broken_backend_in_tx", true);
	}
};

static long long read_admin_counter(const char* var_name) {
	PGconn* admin = open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port,
	                          cl.admin_username, cl.admin_password,
	                          "ProxySQL admin (PgSQL protocol)");
	if (!admin) return -1;
	std::string q = "SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name = '";
	q += var_name;
	q += "'";
	PGresult* r = PQexec(admin, q.c_str());
	long long v = -1;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) {
		v = atoll(PQgetvalue(r, 0, 0));
	}
	PQclear(r);
	PQfinish(admin);
	return v;
}

static int poll_for_marked_backend_pid(const char* marker, int timeout_ms) {
	PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
	                           cl.pgsql_server_username, cl.pgsql_server_password,
	                           "PG-direct (superuser)");
	if (!direct) return -1;
	const char* find =
		"SELECT pid FROM pg_stat_activity "
		"WHERE state = 'active' AND query LIKE '%' || $1 || '%'";
	const char* params[1] = { marker };
	int pid = -1;
	for (int elapsed = 0; elapsed < timeout_ms; elapsed += 100) {
		PGresult* r = PQexecParams(direct, find, 1, nullptr, params, nullptr, nullptr, 0);
		if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) {
			pid = atoi(PQgetvalue(r, 0, 0));
			PQclear(r);
			break;
		}
		PQclear(r);
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
	PQfinish(direct);
	return pid;
}

static bool terminate_backend(int pid) {
	PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
	                           cl.pgsql_server_username, cl.pgsql_server_password,
	                           "PG-direct (superuser)");
	if (!direct) return false;
	char q[96];
	snprintf(q, sizeof(q), "SELECT pg_terminate_backend(%d)", pid);
	PGresult* r = PQexec(direct, q);
	bool ok = (PQresultStatus(r) == PGRES_TUPLES_OK
		&& PQntuples(r) == 1
		&& PQgetvalue(r, 0, 0)[0] == 't');
	PQclear(r);
	PQfinish(direct);
	return ok;
}

// Simple-query pg_sleep + kill → drives session into poisoned state. Poll-based
// kill (no fixed-delay sleep). Returns the PGresult from the sleep query and
// whether the kill actually fired.
struct KillResult {
	PGresult* pgresult = nullptr;
	bool kill_delivered = false;
};

static KillResult poison_via_kill(PGconn* cli, int sleep_secs = 5) {
	char marker[96];
	snprintf(marker, sizeof(marker),
	         "txp_ext_marker_%ld_%d_%ld",
	         (long)time(nullptr), (int)getpid(), (long)rand());
	char sleep_query[256];
	snprintf(sleep_query, sizeof(sleep_query),
	         "SELECT pg_sleep(%d), '%s'", sleep_secs, marker);

	KillResult out;
	std::atomic<bool> did_kill{false};
	std::string local_marker(marker);
	std::thread killer([&did_kill, local_marker]() {
		int pid = poll_for_marked_backend_pid(local_marker.c_str(), /*timeout_ms*/ 6000);
		if (pid <= 0) {
			diag("ext-query poison: marker %s not found within 6s", local_marker.c_str());
			return;
		}
		if (terminate_backend(pid)) did_kill.store(true);
	});
	out.pgresult = PQexec(cli, sleep_query);
	killer.join();
	out.kill_delivered = did_kill.load();
	return out;
}

// Predicate for "extended-query call was rejected with ERROR 25P02 while
// poisoned". Stronger than the earlier version: it also asserts severity=ERROR
// (not FATAL). A regression that emitted FATAL 25P02 would pass a status+
// sqlstate-only check while actually causing libpq to drop the socket.
static bool rejected_25P02_as_error(PGresult* r) {
	if (!r) return false;
	if (PQresultStatus(r) != PGRES_FATAL_ERROR) return false;
	const char* sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	if (!sqlstate || strcmp(sqlstate, "25P02") != 0) return false;
	const char* severity = PQresultErrorField(r, PG_DIAG_SEVERITY);
	if (!severity || strcmp(severity, "ERROR") != 0) return false;
	return true;
}

int main(int /*argc*/, char** /*argv*/) {
	//  1 admin var set true
	//  2 BEGIN (simple)
	//  3 poison pg_sleep returns 25P02 (severity=ERROR, not FATAL)
	//  4 client still CONNECTION_OK + PQTRANS_INERROR
	//  5 PQexecParams while poisoned -> 25P02 severity=ERROR
	//  6 PQprepare while poisoned -> 25P02 severity=ERROR
	//  7 PQexecPrepared while poisoned -> 25P02 severity=ERROR
	//  8 rejected counter incremented by EXACTLY 3 (not >=3 — catches
	//    regressions that over-count)
	//  9 Simple-query ROLLBACK recovers to PQTRANS_IDLE
	// 10 PQexecParams post-recovery returns rows
	// 11 PQprepare + PQexecPrepared post-recovery work
	plan(11);

	srand((unsigned int)time(nullptr) ^ (unsigned int)getpid());

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	RestorePreserveClientAdminVar admin_guard;

	ok(set_admin_bool("preserve_client_on_broken_backend_in_tx", true),
	   "Set pgsql-preserve_client_on_broken_backend_in_tx=true");

	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password, "ProxySQL");
	if (!cli) {
		for (int i = 0; i < 10; ++i) ok(0, "SKIPPED: aborted on connect");
		return exit_status();
	}

	PGresult* r = PQexec(cli, "BEGIN");
	ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	   "BEGIN (simple query) succeeded (%s)", PQresStatus(PQresultStatus(r)));
	PQclear(r);

	long long c_rej_before = read_admin_counter("pgsql_tx_poisoned_rejected_statements_total");

	KillResult kr = poison_via_kill(cli);
	if (!kr.kill_delivered) {
		ok(0, "poison: killer failed to deliver pg_terminate_backend within 6s");
		for (int i = 0; i < 8; ++i) ok(0, "SKIPPED: poison did not fire");
		PQclear(kr.pgresult);
		PQfinish(cli);
		return exit_status();
	}
	ok(rejected_25P02_as_error(kr.pgresult),
	   "pg_sleep after mid-tx backend kill returns 25P02 severity=ERROR (status=%s severity=%s sqlstate=%s)",
	   PQresStatus(PQresultStatus(kr.pgresult)),
	   PQresultErrorField(kr.pgresult, PG_DIAG_SEVERITY) ?: "(none)",
	   PQresultErrorField(kr.pgresult, PG_DIAG_SQLSTATE) ?: "(none)");
	PQclear(kr.pgresult);

	ok(PQstatus(cli) == CONNECTION_OK && PQtransactionStatus(cli) == PQTRANS_INERROR,
	   "Client stays connected in PQTRANS_INERROR after poison (pgstatus=%d, txstate=%d)",
	   (int)PQstatus(cli), (int)PQtransactionStatus(cli));

	// Extended query #1: PQexecParams with no params (still uses P/B/E/S on the wire).
	r = PQexecParams(cli, "SELECT 42", 0, nullptr, nullptr, nullptr, nullptr, 0);
	ok(rejected_25P02_as_error(r),
	   "PQexecParams while poisoned returns 25P02 severity=ERROR");
	PQclear(r);

	// Extended query #2: PQprepare (sends Parse + Sync).
	r = PQprepare(cli, "stmt_poisoned", "SELECT 43", 0, nullptr);
	ok(rejected_25P02_as_error(r),
	   "PQprepare while poisoned returns 25P02 severity=ERROR");
	PQclear(r);

	// Extended query #3: PQexecPrepared (sends Bind + Execute + Sync; the
	// referenced stmt_poisoned wasn't actually created because PQprepare got
	// rejected, but what matters here is ProxySQL's reply shape).
	r = PQexecPrepared(cli, "stmt_poisoned", 0, nullptr, nullptr, nullptr, 0);
	ok(rejected_25P02_as_error(r),
	   "PQexecPrepared while poisoned returns 25P02 severity=ERROR");
	PQclear(r);

	// EXACT counter delta: one increment per logical ext-query call.
	long long c_rej_mid = read_admin_counter("pgsql_tx_poisoned_rejected_statements_total");
	diag("counters: rejected %lld -> %lld (expecting EXACTLY +3 for 3 ext-query calls)",
	     c_rej_before, c_rej_mid);
	ok(c_rej_mid == c_rej_before + 3,
	   "pgsql_tx_poisoned_rejected_statements_total incremented by EXACTLY 3 "
	   "(one per logical ext-query call; a +4/+8/+11 result would indicate "
	   "per-wire-packet counting regressed; before=%lld, after=%lld)",
	   c_rej_before, c_rej_mid);

	// Recovery via Simple-Query ROLLBACK.
	r = PQexec(cli, "ROLLBACK");
	ok(PQresultStatus(r) == PGRES_COMMAND_OK && PQtransactionStatus(cli) == PQTRANS_IDLE,
	   "Simple-query ROLLBACK recovers poisoned session (status=%s, txn=%d)",
	   PQresStatus(PQresultStatus(r)), (int)PQtransactionStatus(cli));
	PQclear(r);

	// Extended query post-recovery returns rows.
	r = PQexecParams(cli, "SELECT 1", 0, nullptr, nullptr, nullptr, nullptr, 0);
	ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1,
	   "PQexecParams post-recovery returns rows (status=%s ntuples=%d)",
	   PQresStatus(PQresultStatus(r)), PQntuples(r));
	PQclear(r);

	// Fresh prepared statement post-recovery works.
	r = PQprepare(cli, "stmt_recovered", "SELECT $1::int + 1", 0, nullptr);
	bool prep_ok = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	const char* params[1] = { "41" };
	r = PQexecPrepared(cli, "stmt_recovered", 1, params, nullptr, nullptr, 0);
	bool exec_ok = (PQresultStatus(r) == PGRES_TUPLES_OK
		&& PQntuples(r) == 1
		&& strcmp(PQgetvalue(r, 0, 0), "42") == 0);
	PQclear(r);
	ok(prep_ok && exec_ok,
	   "PQprepare + PQexecPrepared post-recovery execute cleanly (prepare=%s exec=%s)",
	   prep_ok ? "ok" : "fail", exec_ok ? "ok" : "fail");

	PQfinish(cli);
	return exit_status();
}
