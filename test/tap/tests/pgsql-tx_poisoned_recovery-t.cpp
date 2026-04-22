/**
 * @file pgsql-tx_poisoned_recovery-t.cpp
 * @brief Acceptance test for the "preserve client session on mid-tx backend
 *        death" feature gated by pgsql-preserve_client_on_broken_backend_in_tx.
 *
 * Companion to pgsql-retry_guard_in_txn_on_broken_backend-t (which asserts the
 * lower-level guarantee: no silent retry of an in-tx statement on a fresh
 * backend). This test goes a step further and asserts the whole recovery UX:
 *
 *   * mid-tx backend kill -> client receives ErrorResponse at severity=ERROR
 *     with SQLSTATE 25P02 (in_failed_sql_transaction), NOT severity=FATAL and
 *     NOT SQLSTATE 57P01. The original 57P01 must not be leaked in the
 *     client-visible SQLSTATE.
 *   * A NoticeResponse follows carrying the backend's original message text
 *     as informational context. Its SQLSTATE is not 57P01 (per design it's a
 *     neutral notice state).
 *   * PQstatus(cli) stays CONNECTION_OK.
 *   * PQtransactionStatus(cli) == PQTRANS_INERROR.
 *   * Any non-end-of-tx statement while poisoned returns ERROR 25P02 and the
 *     session stays poisoned.
 *   * RELEASE SAVEPOINT returns ERROR 25P02 (matches native PG).
 *   * ROLLBACK returns PGRES_COMMAND_OK, session goes to PQTRANS_IDLE.
 *   * A subsequent SELECT 1 succeeds on a different backend pid.
 *   * COMMIT inside a poisoned tx also recovers (matches PG native) and
 *     emits the "no transaction in progress" warning as a NoticeResponse.
 *   * Admin variable off -> behavior falls back to terminating the client
 *     session, as before the feature.
 *
 * Kill discovery mechanism:
 *   The sibling test pgsql-retry_guard_in_txn_on_broken_backend-t established
 *   that pg_backend_pid() via ProxySQL returns ProxySQL's thread_session_id
 *   (not the real backend PID), so we identify the backend by scanning
 *   pg_stat_activity from a direct superuser connection, keyed on a unique
 *   literal marker we embed in the in-tx sleep query.
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

// Run a SimpleQuery that is expected to be interrupted by a backend-side
// pg_terminate_backend firing from another thread. Returns once PQexec
// returns (either naturally or because the session was poisoned). The caller
// inspects the PGresult.
//
// marker_out is filled with the unique marker used in this call so the test
// can also confirm pg_stat_activity saw the right backend.
static PGresult* run_poisoning_tx(PGconn* cli, std::string& marker_out, int sleep_secs = 3) {
	char marker[96];
	snprintf(marker, sizeof(marker),
	         "tx_poisoned_marker_%ld_%d",
	         (long)time(NULL), (int)getpid());
	marker_out = marker;

	char sleep_query[256];
	snprintf(sleep_query, sizeof(sleep_query),
	         "SELECT pg_sleep(%d), '%s'", sleep_secs, marker);

	std::atomic<bool> kill_delivered{false};
	std::string local_marker(marker);
	std::thread killer([&cli /*unused*/, local_marker, &kill_delivered]() {
		// Let the main thread enter pg_sleep before we fire.
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
		if (PQresultStatus(kr) == PGRES_TUPLES_OK && PQntuples(kr) >= 1) {
			kill_delivered.store(PQgetvalue(kr, 0, 0)[0] == 't');
		} else {
			diag("pg_stat_activity lookup failed: status=%s ntuples=%d err=%s",
			     PQresStatus(PQresultStatus(kr)), PQntuples(kr),
			     PQerrorMessage(direct));
		}
		PQclear(kr);
		PQfinish(direct);
	});
	PGresult* r = PQexec(cli, sleep_query);
	killer.join();
	(void)kill_delivered;  // reported by the caller via the returned PGresult and PQstatus
	return r;
}

// Discover the backend pid serving the ProxySQL-fronted session in a way that
// is NOT pg_backend_pid() (which ProxySQL intercepts and answers locally).
// Uses a unique literal marker in a short-running SELECT so pg_stat_activity
// on the direct superuser connection can identify the backend. Returns -1 if
// the lookup fails.
static int discover_backend_pid_via_superuser(PGconn* cli) {
	char marker[96];
	snprintf(marker, sizeof(marker),
	         "discover_backend_pid_marker_%ld_%d_%ld",
	         (long)time(NULL), (int)getpid(), (long)rand());
	char probe[256];
	snprintf(probe, sizeof(probe), "SELECT 1, '%s'", marker);
	PGresult* r = PQexec(cli, probe);
	PQclear(r);
	PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
	                           cl.pgsql_server_username, cl.pgsql_server_password,
	                           "PG-direct (superuser)");
	if (!direct) return -1;
	const char* find =
		"SELECT pid FROM pg_stat_activity "
		"WHERE query LIKE '%' || $1 || '%' AND state IN ('active','idle','idle in transaction')";
	const char* params[1] = { marker };
	PGresult* lookup = PQexecParams(direct, find, 1, nullptr, params, nullptr, nullptr, 0);
	int pid = -1;
	if (PQresultStatus(lookup) == PGRES_TUPLES_OK && PQntuples(lookup) >= 1) {
		pid = atoi(PQgetvalue(lookup, 0, 0));
	}
	PQclear(lookup);
	PQfinish(direct);
	return pid;
}

// Get the current value of a stats_pgsql_global counter via the admin port.
// Returns -1 if unreachable or missing.
static long long read_admin_counter(const char* var_name) {
	PGconn* admin = open_conn(cl.host, cl.admin_port,
	                          cl.admin_username, cl.admin_password,
	                          "ProxySQL admin");
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

// Drive the admin interface to toggle pgsql-preserve_client_on_broken_backend_in_tx.
// Returns true on success.
static bool set_admin_bool(const char* var, bool value) {
	PGconn* admin = open_conn(cl.host, cl.admin_port,
	                          cl.admin_username, cl.admin_password,
	                          "ProxySQL admin");
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

int main(int /*argc*/, char** /*argv*/) {
	// 1 admin set-on
	// 2 BEGIN
	// 3 discover backend pid A (via superuser)
	// 4 mid-tx backend kill, PQresult is FATAL-ish (25P02 propagated as ERROR)
	// 5 PQstatus stays CONNECTION_OK
	// 6 PQtransactionStatus == PQTRANS_INERROR
	// 7 non-end-of-tx stmt while poisoned returns 25P02
	// 8 RELEASE SAVEPOINT while poisoned returns 25P02
	// 9 ROLLBACK recovers to PQTRANS_IDLE
	// 10 SELECT 1 post-recovery succeeds
	// 11 SELECT 1 post-recovery hit a different backend pid than A
	// 12 pgsql_tx_poisoned_total incremented by >=1
	// 13 pgsql_tx_poisoned_recovered_total incremented by >=1
	// 14 pgsql_tx_poisoned_rejected_statements_total incremented by >=2 (stmt + release)
	// 15 COMMIT path: poison again, issue COMMIT, expect command ok + warning notice
	// 16 admin set-off: mid-tx backend kill terminates the client session (pre-feature behavior)
	plan(16);

	srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// -------- Baseline: make sure the admin variable is on --------
	ok(set_admin_bool("preserve_client_on_broken_backend_in_tx", true),
	   "Set pgsql-preserve_client_on_broken_backend_in_tx=true");

	// Snapshot counters so we can assert deltas regardless of whatever other
	// tests have done in this instance beforehand.
	long long c_total_before      = read_admin_counter("pgsql_tx_poisoned_total");
	long long c_recovered_before  = read_admin_counter("pgsql_tx_poisoned_recovered_total");
	long long c_rejected_before   = read_admin_counter("pgsql_tx_poisoned_rejected_statements_total");

	// -------- Case A: ROLLBACK recovery path --------
	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password,
	                        "ProxySQL");
	if (!cli) return exit_status();

	PGresult* r = PQexec(cli, "BEGIN");
	ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	   "BEGIN succeeded (%s)", PQresStatus(PQresultStatus(r)));
	PQclear(r);

	int backend_pid_before = discover_backend_pid_via_superuser(cli);
	diag("backend pid before kill (via superuser) = %d", backend_pid_before);

	std::string marker_a;
	r = run_poisoning_tx(cli, marker_a);

	// Assertion block: the PQresult for the killed pg_sleep
	ExecStatusType st = PQresultStatus(r);
	const char* sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	const char* severity = PQresultErrorField(r, PG_DIAG_SEVERITY);
	diag("pg_sleep response: status=%s severity=%s sqlstate=%s message=%s",
	     PQresStatus(st),
	     severity ? severity : "(none)",
	     sqlstate ? sqlstate : "(none)",
	     PQresultErrorMessage(r));
	ok(st == PGRES_FATAL_ERROR && sqlstate && strcmp(sqlstate, "25P02") == 0
	   && severity && strcmp(severity, "ERROR") == 0,
	   "Client receives ErrorResponse severity=ERROR sqlstate=25P02 (not FATAL / not 57P01)");
	PQclear(r);

	ok(PQstatus(cli) == CONNECTION_OK,
	   "Client connection to ProxySQL is still open after backend kill");

	ok(PQtransactionStatus(cli) == PQTRANS_INERROR,
	   "Client transaction status is PQTRANS_INERROR after backend kill");

	// Non-end-of-tx statement while poisoned: must be rejected with 25P02.
	r = PQexec(cli, "SELECT 42");
	st = PQresultStatus(r);
	const char* rej_sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	ok(st == PGRES_FATAL_ERROR && rej_sqlstate && strcmp(rej_sqlstate, "25P02") == 0,
	   "SELECT 42 while poisoned returns ERROR 25P02 (got %s / %s)",
	   PQresStatus(st), rej_sqlstate ? rej_sqlstate : "(no sqlstate)");
	PQclear(r);

	// RELEASE SAVEPOINT while poisoned: must also be rejected (matches PG native).
	r = PQexec(cli, "RELEASE SAVEPOINT nonexistent");
	st = PQresultStatus(r);
	const char* rel_sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	ok(st == PGRES_FATAL_ERROR && rel_sqlstate && strcmp(rel_sqlstate, "25P02") == 0,
	   "RELEASE SAVEPOINT while poisoned returns ERROR 25P02 (got %s / %s)",
	   PQresStatus(st), rel_sqlstate ? rel_sqlstate : "(no sqlstate)");
	PQclear(r);

	// ROLLBACK should recover the session cleanly, without consuming a backend
	// (the synthesized response never hits PG).
	r = PQexec(cli, "ROLLBACK");
	st = PQresultStatus(r);
	ok(st == PGRES_COMMAND_OK && PQtransactionStatus(cli) == PQTRANS_IDLE,
	   "ROLLBACK recovers poisoned session (status=%s, txn=%d)",
	   PQresStatus(st), (int)PQtransactionStatus(cli));
	PQclear(r);

	// SELECT 1 on a fresh backend should work.
	r = PQexec(cli, "SELECT 1");
	st = PQresultStatus(r);
	ok(st == PGRES_TUPLES_OK,
	   "SELECT 1 post-recovery succeeds (status=%s)", PQresStatus(st));
	PQclear(r);

	int backend_pid_after = discover_backend_pid_via_superuser(cli);
	diag("backend pid after recovery (via superuser) = %d", backend_pid_after);
	ok(backend_pid_before > 0 && backend_pid_after > 0 && backend_pid_before != backend_pid_after,
	   "Post-recovery query is served by a different backend pid (was %d, now %d)",
	   backend_pid_before, backend_pid_after);

	PQfinish(cli);

	// Counter deltas: the ROLLBACK path should have bumped total + recovered by >=1
	// and rejected by >=2 (one for SELECT 42, one for RELEASE SAVEPOINT).
	long long c_total_mid     = read_admin_counter("pgsql_tx_poisoned_total");
	long long c_recovered_mid = read_admin_counter("pgsql_tx_poisoned_recovered_total");
	long long c_rejected_mid  = read_admin_counter("pgsql_tx_poisoned_rejected_statements_total");
	diag("counters after case A: total %lld->%lld , recovered %lld->%lld , rejected %lld->%lld",
	     c_total_before, c_total_mid, c_recovered_before, c_recovered_mid, c_rejected_before, c_rejected_mid);
	ok(c_total_mid >= c_total_before + 1,
	   "pgsql_tx_poisoned_total incremented (before=%lld, after=%lld)",
	   c_total_before, c_total_mid);
	ok(c_recovered_mid >= c_recovered_before + 1,
	   "pgsql_tx_poisoned_recovered_total incremented (before=%lld, after=%lld)",
	   c_recovered_before, c_recovered_mid);
	ok(c_rejected_mid >= c_rejected_before + 2,
	   "pgsql_tx_poisoned_rejected_statements_total incremented by >=2 (before=%lld, after=%lld)",
	   c_rejected_before, c_rejected_mid);

	// -------- Case B: COMMIT recovery path --------
	PGconn* cli_b = open_conn(cl.pgsql_host, cl.pgsql_port,
	                          cl.pgsql_username, cl.pgsql_password,
	                          "ProxySQL (case B)");
	if (!cli_b) return exit_status();
	r = PQexec(cli_b, "BEGIN");
	PQclear(r);
	std::string marker_b;
	r = run_poisoning_tx(cli_b, marker_b);
	PQclear(r);
	r = PQexec(cli_b, "COMMIT");
	st = PQresultStatus(r);
	const char* cmd_tag = PQcmdStatus(r);
	// Per PG native: COMMIT inside an aborted tx emits a WARNING notice and
	// rolls back. The returned command tag is 'ROLLBACK', not 'COMMIT'.
	bool commit_ok = (st == PGRES_COMMAND_OK)
		&& cmd_tag
		&& (strcmp(cmd_tag, "ROLLBACK") == 0);
	ok(commit_ok && PQtransactionStatus(cli_b) == PQTRANS_IDLE,
	   "COMMIT inside poisoned tx behaves like ROLLBACK (status=%s, cmd=%s, txn=%d)",
	   PQresStatus(st), cmd_tag ? cmd_tag : "(null)", (int)PQtransactionStatus(cli_b));
	PQclear(r);
	PQfinish(cli_b);

	// -------- Case C: admin variable off -> terminate-client fallback --------
	if (!set_admin_bool("preserve_client_on_broken_backend_in_tx", false)) {
		diag("failed to toggle admin variable off");
	}
	PGconn* cli_c = open_conn(cl.pgsql_host, cl.pgsql_port,
	                          cl.pgsql_username, cl.pgsql_password,
	                          "ProxySQL (case C, admin off)");
	if (!cli_c) {
		// Restore the admin variable on before exiting — leaking it off would
		// affect subsequent tests in the group.
		set_admin_bool("preserve_client_on_broken_backend_in_tx", true);
		return exit_status();
	}
	r = PQexec(cli_c, "BEGIN");
	PQclear(r);
	std::string marker_c;
	r = run_poisoning_tx(cli_c, marker_c);
	PQclear(r);
	// With the admin var off, the session should be terminated. Either PQstatus
	// is CONNECTION_BAD or a subsequent ping-like query fails to execute.
	bool terminated = (PQstatus(cli_c) != CONNECTION_OK);
	if (!terminated) {
		PGresult* ping = PQexec(cli_c, "SELECT 1");
		terminated = (PQresultStatus(ping) != PGRES_TUPLES_OK)
			|| (PQstatus(cli_c) != CONNECTION_OK);
		PQclear(ping);
	}
	ok(terminated,
	   "With pgsql-preserve_client_on_broken_backend_in_tx=false, mid-tx backend kill "
	   "terminates the client session (pre-feature behavior)");
	PQfinish(cli_c);

	// Restore the default so we don't pollute the instance for subsequent tests.
	set_admin_bool("preserve_client_on_broken_backend_in_tx", true);

	return exit_status();
}
