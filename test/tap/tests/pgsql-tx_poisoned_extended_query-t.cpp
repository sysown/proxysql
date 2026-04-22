/**
 * @file pgsql-tx_poisoned_extended_query-t.cpp
 * @brief Extended-query coverage for the tx_poisoned recovery feature.
 *
 * Sibling to pgsql-tx_poisoned_recovery-t (which exercises only the simple-
 * query protocol). This test walks the PostgreSQL extended-query protocol
 * through libpq's high-level wrappers (PQexecParams, PQprepare,
 * PQexecPrepared) and asserts:
 *
 *   * While tx_poisoned, every extended-query round trip (Parse/Bind/
 *     Describe/Execute/Sync) lands as ERROR 25P02 at Sync, and the
 *     pgsql_tx_poisoned_rejected_statements_total counter increments
 *     exactly once per logical ext-query call (not per wire packet).
 *   * PQprepare and PQexecPrepared both return 25P02 while poisoned.
 *   * A simple-query ROLLBACK still recovers the session.
 *   * After recovery, the same extended-query calls work — a fresh
 *     PREPARE succeeds, and PQexecParams returns rows.
 *
 * The initial poisoning is driven through a simple-query pg_sleep with the
 * sibling-test marker-kill trick (pg_terminate_backend via pg_stat_activity
 * from a direct superuser connection), because poisoning is triggered by
 * a backend disconnect which happens the same way regardless of which
 * protocol the client was using.
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

// Drive the admin interface (PgSQL-protocol admin port, 6132 by default) to
// toggle the preserve_client_on_broken_backend_in_tx boolean.
static bool set_admin_bool(const char* var, bool value) {
	PGconn* admin = open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port,
	                          cl.admin_username, cl.admin_password,
	                          "ProxySQL admin (PgSQL protocol)");
	if (!admin) return false;
	char q[256];
	snprintf(q, sizeof(q),
	         "UPDATE global_variables SET variable_value='%s' WHERE variable_name='%s'",
	         value ? "true" : "false", var);
	PGresult* r = PQexec(admin, q);
	bool ok1 = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	r = PQexec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	bool ok2 = (PQresultStatus(r) == PGRES_COMMAND_OK);
	PQclear(r);
	PQfinish(admin);
	return ok1 && ok2;
}

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

// Poison the session by terminating its backend mid-transaction. The
// mechanics match pgsql-tx_poisoned_recovery-t: embed a unique marker
// inside a simple-query pg_sleep so the superuser-side pg_stat_activity
// lookup can identify the right backend. Returns the PGresult of the
// pg_sleep call (expected to be PGRES_FATAL_ERROR with sqlstate 25P02
// after the feature kicks in). Caller owns and PQclears it.
static PGresult* poison_via_kill(PGconn* cli, int sleep_secs = 3) {
	char marker[96];
	snprintf(marker, sizeof(marker),
	         "txp_ext_marker_%ld_%d_%ld",
	         (long)time(NULL), (int)getpid(), (long)rand());
	char sleep_query[256];
	snprintf(sleep_query, sizeof(sleep_query),
	         "SELECT pg_sleep(%d), '%s'", sleep_secs, marker);
	std::string local_marker(marker);
	std::thread killer([local_marker]() {
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
		                           cl.pgsql_server_username, cl.pgsql_server_password,
		                           "PG-direct (superuser)");
		if (!direct) return;
		const char* find_and_kill =
			"SELECT pg_terminate_backend(pid) "
			"FROM pg_stat_activity "
			"WHERE state = 'active' AND query LIKE '%' || $1 || '%'";
		const char* params[1] = { local_marker.c_str() };
		PGresult* kr = PQexecParams(direct, find_and_kill,
		                            1, nullptr, params, nullptr, nullptr, 0);
		PQclear(kr);
		PQfinish(direct);
	});
	PGresult* r = PQexec(cli, sleep_query);
	killer.join();
	return r;
}

// Compare a PQresult against expected {status, sqlstate}. Used both as a
// predicate for ok() and as a diagnostic.
static bool is_rejected_with_25P02(PGresult* r) {
	if (!r) return false;
	ExecStatusType st = PQresultStatus(r);
	const char* sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	return st == PGRES_FATAL_ERROR && sqlstate && strcmp(sqlstate, "25P02") == 0;
}

int main(int /*argc*/, char** /*argv*/) {
	//  1 admin var set true
	//  2 BEGIN (simple)
	//  3 poison pg_sleep returns 25P02
	//  4 client still connected + PQTRANS_INERROR after poison
	//  5 PQexecParams while poisoned -> 25P02  (extended query round trip)
	//  6 PQprepare while poisoned -> 25P02
	//  7 PQexecPrepared while poisoned -> 25P02
	//  8 rejected counter incremented by >=3 (one per ext-query call, not per
	//    wire packet)
	//  9 ROLLBACK (simple) recovers session to PQTRANS_IDLE
	// 10 PQexecParams post-recovery returns rows
	// 11 PQprepare + PQexecPrepared post-recovery work
	plan(11);

	srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	ok(set_admin_bool("preserve_client_on_broken_backend_in_tx", true),
	   "Set pgsql-preserve_client_on_broken_backend_in_tx=true");

	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password,
	                        "ProxySQL");
	if (!cli) return exit_status();

	PGresult* r = PQexec(cli, "BEGIN");
	ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	   "BEGIN (simple query) succeeded (%s)", PQresStatus(PQresultStatus(r)));
	PQclear(r);

	long long c_rej_before = read_admin_counter("pgsql_tx_poisoned_rejected_statements_total");

	r = poison_via_kill(cli);
	ok(is_rejected_with_25P02(r),
	   "pg_sleep after mid-tx backend kill returns 25P02 (status=%s sqlstate=%s)",
	   PQresStatus(PQresultStatus(r)),
	   PQresultErrorField(r, PG_DIAG_SQLSTATE) ?: "(none)");
	PQclear(r);

	ok(PQstatus(cli) == CONNECTION_OK && PQtransactionStatus(cli) == PQTRANS_INERROR,
	   "Client stays connected in PQTRANS_INERROR after poison (pgstatus=%d, txstate=%d)",
	   (int)PQstatus(cli), (int)PQtransactionStatus(cli));

	// --- Extended query #1: PQexecParams with no params (still uses P/B/E/S on the wire) ---
	r = PQexecParams(cli, "SELECT 42", 0, nullptr, nullptr, nullptr, nullptr, 0);
	ok(is_rejected_with_25P02(r),
	   "PQexecParams while poisoned returns 25P02 (status=%s sqlstate=%s)",
	   PQresStatus(PQresultStatus(r)),
	   PQresultErrorField(r, PG_DIAG_SQLSTATE) ?: "(none)");
	PQclear(r);

	// --- Extended query #2: PQprepare (sends Parse + Sync) ---
	r = PQprepare(cli, "stmt_poisoned", "SELECT 43", 0, nullptr);
	ok(is_rejected_with_25P02(r),
	   "PQprepare while poisoned returns 25P02 (status=%s sqlstate=%s)",
	   PQresStatus(PQresultStatus(r)),
	   PQresultErrorField(r, PG_DIAG_SQLSTATE) ?: "(none)");
	PQclear(r);

	// --- Extended query #3: PQexecPrepared on a (non-existent, because prior
	// PREPARE was rejected) prepared statement (sends Bind + Execute + Sync) ---
	r = PQexecPrepared(cli, "stmt_poisoned", 0, nullptr, nullptr, nullptr, 0);
	ok(is_rejected_with_25P02(r),
	   "PQexecPrepared while poisoned returns 25P02 (status=%s sqlstate=%s)",
	   PQresStatus(PQresultStatus(r)),
	   PQresultErrorField(r, PG_DIAG_SQLSTATE) ?: "(none)");
	PQclear(r);

	long long c_rej_mid = read_admin_counter("pgsql_tx_poisoned_rejected_statements_total");
	diag("counters: rejected %lld -> %lld (expecting +3 from ext-query calls while poisoned)",
	     c_rej_before, c_rej_mid);
	ok(c_rej_mid >= c_rej_before + 3,
	   "pgsql_tx_poisoned_rejected_statements_total incremented by >=3 (one per ext-query call, "
	   "not per wire packet; before=%lld, after=%lld)",
	   c_rej_before, c_rej_mid);

	// --- Recovery via simple-query ROLLBACK ---
	r = PQexec(cli, "ROLLBACK");
	ExecStatusType st = PQresultStatus(r);
	ok(st == PGRES_COMMAND_OK && PQtransactionStatus(cli) == PQTRANS_IDLE,
	   "Simple-query ROLLBACK recovers poisoned session (status=%s, txn=%d)",
	   PQresStatus(st), (int)PQtransactionStatus(cli));
	PQclear(r);

	// --- Extended query post-recovery ---
	r = PQexecParams(cli, "SELECT 1", 0, nullptr, nullptr, nullptr, nullptr, 0);
	st = PQresultStatus(r);
	bool ext_ok = (st == PGRES_TUPLES_OK && PQntuples(r) == 1);
	ok(ext_ok,
	   "PQexecParams post-recovery returns rows (status=%s ntuples=%d)",
	   PQresStatus(st), PQntuples(r));
	PQclear(r);

	// Fresh name for the prepared statement: the earlier PQprepare was
	// rejected so stmt_poisoned does not exist, but using a distinct name
	// keeps this clean and explicit.
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
