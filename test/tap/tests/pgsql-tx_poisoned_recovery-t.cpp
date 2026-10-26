/**
 * @file pgsql-tx_poisoned_recovery-t.cpp
 * @brief Acceptance test for the "preserve client session on mid-tx backend
 *        death" feature gated by pgsql-preserve_client_on_broken_backend_in_tx.
 *
 * Companion to pgsql-retry_guard_in_txn_on_broken_backend-t (lower-level no-
 * silent-retry guard) and pgsql-tx_poisoned_extended_query-t (extended-query
 * coverage for the same feature).
 *
 * What this test asserts end-to-end:
 *   * Mid-tx backend kill surfaces to the client as
 *     ErrorResponse(severity=ERROR, SQLSTATE=25P02), NOT FATAL and NOT 57P01.
 *   * Alongside the ErrorResponse, a NoticeResponse carries the backend's
 *     original message text at SQLSTATE 01000 (WARNING) — the original 57P01
 *     is suppressed, and the asserted 01000 catches regressions that might
 *     revert to 00000 (successful_completion) or leak 57P01.
 *   * Client stays CONNECTION_OK in PQTRANS_INERROR.
 *   * Non-end-of-tx statements are rejected with 25P02, session stays poisoned.
 *   * RELEASE SAVEPOINT, ROLLBACK TO SAVEPOINT, and multi-statement ROLLBACK
 *     are also rejected (see implementation's classifier — we can't honor
 *     savepoint-level rollback on a dead backend, and we won't silently drop
 *     a pipelined second statement).
 *   * Word-boundary in the classifier — "ROLLBACKET" does not trigger recovery.
 *   * ROLLBACK (plain), ROLLBACK WORK, and COMMIT recover the session. COMMIT
 *     answers with the ROLLBACK command tag and no notice, as PG native does
 *     (the 25P01 "no transaction in progress" warning is only for a COMMIT
 *     outside any transaction).
 *   * Post-recovery queries hit a different backend PID (poison path destroyed
 *     the pool connection, a fresh one was acquired on the next query).
 *   * Three stats counters increment with EXACT expected deltas.
 *   * Non-tx statement killed mid-flight does NOT trigger poison (we gate on
 *     is_in_transaction(), not the disconnect heuristic).
 *   * Admin variable off → mid-tx backend kill terminates the client session
 *     (pre-feature fallback), and none of the tx-poisoned counters move.
 *   * A COMMIT (or PREPARE TRANSACTION) whose backend dies before answering is
 *     never answered 25P02: it may have committed, so the client is
 *     disconnected, over the simple and extended protocol, in a multi-statement
 *     query and in a pipeline. A pipelined COMMIT the backend confirmed is
 *     reported OK or the client disconnected, never answered 25P02. Without a
 *     COMMIT in flight (a pipeline, an SQL PREPARE) the session is still
 *     poisoned. Run with the libpq and the native backend protocol.
 *   * A backend that dies holding session state (session advisory lock, temp
 *     table, SQL PREPARE, WITH HOLD cursor, temp sequence, LISTEN) disconnects
 *     the client instead of poisoning: the state is gone. A savepoint and a
 *     transaction advisory lock still poison, and so do a tracked SET and state
 *     released again (pg_advisory_unlock_all, DISCARD TEMP, CLOSE ALL). The state
 *     may be taken in the killed transaction, an earlier one or over the extended
 *     protocol; an untracked SET counts. A multiplex=0 rule alone is no state: the
 *     client is still poisoned. Run with both protocols.
 *   * An error ProxySQL raises itself inside a transaction (a rejected DISCARD ALL,
 *     a query rule's error_msg) poisons the session with the backend alive. Ending it
 *     (ROLLBACK or COMMIT, simple or extended protocol) rolls the backend back instead
 *     of dropping it, so a session advisory lock survives and the work is not committed.
 *     The next statement may go to another hostgroup or be pipelined right behind
 *     the ROLLBACK (over either protocol), and SET values changed in the transaction are
 *     back afterwards. Run with both protocols.
 *   * Cases F and G run in four TLS variants per backend protocol: the client talks TLS
 *     to the proxy or not, the proxy talks TLS to the backend or not. Each variant checks,
 *     from PostgreSQL's side, that the backend leg is what it was set to.
 *
 * Flakiness-resistance measures:
 *   * The killer thread polls pg_stat_activity up to ~6 s in 100 ms ticks for
 *     the marker it embedded in the victim query, and reports whether the
 *     kill was delivered. The test fails with a clear diag if the kill didn't
 *     fire, rather than silently cascading into misleading assertion failures.
 *   * The admin variable is restored on every exit path (including failure
 *     paths) via a scope-guard destructor.
 *
 * Backend-pid discovery does NOT use pg_backend_pid() — ProxySQL intercepts
 * that and returns its own thread_session_id. We scan pg_stat_activity from
 * a direct superuser connection with a unique marker query instead.
 */

#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <sstream>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <functional>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

CommandLine cl;

// Whether the clients opened by open_proxy() use TLS: the TLS variants of cases F and G turn it on.
static bool g_client_tls = false;

static PGconn* open_conn(const char* host, int port,
                         const char* user, const char* password,
                         const char* label, const char* sslmode = "disable") {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port;
	ss << " user=" << user << " password=" << password;
	ss << " sslmode=" << sslmode;
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
	// Admin stores PgSQL admin vars with the 'pgsql-' prefix in the
	// variable_name column. Using just the short name would make the UPDATE
	// match 0 rows and silently leave the runtime value unchanged.
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
	// The admin-var variables are per-PgSQL-thread __thread copies, refreshed
	// on each thread's next poll() iteration after LOAD PGSQL VARIABLES TO
	// RUNTIME bumps __global_PgSQL_Thread_Variables_version. LOAD returns
	// immediately on the admin thread, but each worker picks up the new value
	// only when its poll returns (timeout = pgsql-poll_timeout, default 2 s).
	// Case D in particular asserts "admin off → no counter moves", and we
	// don't control which worker handles the victim client, so we must make
	// sure EVERY worker has refreshed before the next operation.
	//
	// Strategy: open a burst of short-lived throwaway PGconns right now. Each
	// new connection triggers activity on one PgSQL worker (round-robin-ish),
	// which returns from poll() and runs the version check. Doing this
	// ~3×num_threads times with tiny delays makes it statistically certain
	// every worker has had at least one activity-wake since the LOAD.
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

// Restore the admin variable to `true` on scope exit, even if the test aborts
// early. Without this, a mid-test crash between "set false" and "set true
// again" would leak admin=false into subsequent tests in the group.
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

struct Counters {
	long long total = 0;
	long long recovered = 0;
	long long rejected = 0;
};

static Counters read_counters() {
	return {
		read_admin_counter("pgsql_tx_poisoned_total"),
		read_admin_counter("pgsql_tx_poisoned_recovered_total"),
		read_admin_counter("pgsql_tx_poisoned_rejected_statements_total")
	};
}

// Collect NoticeResponse payloads on a PGconn so we can later inspect them.
struct NoticeCollector {
	std::vector<PGresult*> notices;
	static void callback(void* arg, const PGresult* res) {
		NoticeCollector* self = static_cast<NoticeCollector*>(arg);
		// Dup the PGresult so we can outlive the libpq-owned original.
		PGresult* dup = PQmakeEmptyPGresult(nullptr, PGRES_NONFATAL_ERROR);
		(void)res;
		if (!dup) return;
		// We can't deep-copy arbitrary PGresult state via public libpq, so
		// instead stash the severity + sqlstate + message as synthesized fields.
		// Callers of this helper that need finer-grained inspection would read
		// the original PGresult; for our assertions the three fields suffice.
		// Store the three fields by overloading the PGresult's error message.
		// libpq provides no public setter for PG_DIAG_SEVERITY etc., so we
		// keep a side-car copy instead.
		(void)dup;
	}
	// Simpler approach: use PQnoticeProcessor (the text-message processor)
	// plus a parallel SQLSTATE/severity capture via PQsetNoticeReceiver on
	// a fresh PGresult stream — but PGresult fields aren't settable. We work
	// around that by capturing the raw text the backend was going to print.
};

// Simplified, working notice collector: we capture the *text* libpq would
// normally print (via PQsetNoticeProcessor) plus a parallel stash of sqlstate
// strings pulled from each notice (via PQsetNoticeReceiver). Both callbacks
// fire for the same notice, so we record once per callback invocation.
struct CapturedNotice {
	std::string severity;
	std::string sqlstate;
	std::string message;
};

struct NoticeBag {
	std::vector<CapturedNotice> items;
};

static void notice_receiver_cb(void* arg, const PGresult* res) {
	NoticeBag* bag = static_cast<NoticeBag*>(arg);
	CapturedNotice n;
	const char* s = PQresultErrorField(res, PG_DIAG_SEVERITY);
	if (s) n.severity = s;
	const char* c = PQresultErrorField(res, PG_DIAG_SQLSTATE);
	if (c) n.sqlstate = c;
	const char* m = PQresultErrorField(res, PG_DIAG_MESSAGE_PRIMARY);
	if (m) n.message = m;
	bag->items.push_back(std::move(n));
}

// Poll pg_stat_activity from the direct superuser connection for a backend
// whose current query contains `marker`. Retry up to `timeout_ms` in 100 ms
// ticks. Returns the PID (>0) on success, -1 if the backend was not found in
// time.
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

// Terminate the backend with the given pid via a direct superuser connection.
// Returns true iff pg_terminate_backend returned 't'.
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

struct KillResult {
	PGresult* pgresult = nullptr;   // PQexec result for the in-flight query
	bool kill_delivered = false;    // true iff superuser successfully terminated the backend
	int victim_pid = -1;            // the PID that got killed (-1 if not found)
};

// Runs send() while a killer thread finds the backend whose running query holds `marker`
// and terminates it. The caller keeps whatever send() got back.
template <typename F>
static KillResult run_with_kill(const std::string& marker, F send) {
	KillResult out;
	std::atomic<bool> did_kill{false};
	std::atomic<int> victim{-1};
	std::thread killer([&did_kill, &victim, marker]() {
		int pid = poll_for_marked_backend_pid(marker.c_str(), /*timeout_ms*/ 6000);
		if (pid <= 0) {
			diag("poll_for_marked_backend_pid: no backend found with marker=%s within 6s",
			     marker.c_str());
			return;
		}
		victim.store(pid);
		if (!terminate_backend(pid)) {
			diag("terminate_backend(%d) returned false", pid);
			return;
		}
		did_kill.store(true);
	});

	send();
	killer.join();
	out.kill_delivered = did_kill.load();
	out.victim_pid = victim.load();
	return out;
}

static std::string new_marker() {
	char marker[96];
	snprintf(marker, sizeof(marker),
	         "txp_recov_marker_%ld_%d_%ld",
	         (long)time(nullptr), (int)getpid(), (long)rand());
	return marker;
}

// Execute a Simple Query that we arrange to be interrupted mid-flight by a
// superuser pg_terminate_backend. The test uses this to drive the session
// into the poisoned state. The caller owns the returned PGresult.
//
// Flake-resistance: the killer thread polls pg_stat_activity until it finds
// the victim backend (up to 6 s), then fires pg_terminate_backend. We expose
// BOTH the PGresult and a `kill_delivered` flag so the caller can distinguish
// "ProxySQL emitted no ERROR because the feature regressed" from "ProxySQL
// emitted no ERROR because the kill never fired on this flaky run".
static KillResult run_poisoning_query(PGconn* cli, const char* in_tx_sql, int sleep_secs = 5) {
	const std::string marker_str = new_marker();
	const char* marker = marker_str.c_str();
	// The victim query embeds the marker so pg_stat_activity can find it, and
	// the `in_tx_sql` parameter lets callers substitute what gets executed
	// (poison variants exercise different verbs).
	std::string query;
	if (in_tx_sql && in_tx_sql[0] != '\0') {
		query = in_tx_sql;
		// Append the marker as a trailing comment so ProxySQL's digest is
		// unaffected and pg_stat_activity still sees it.
		query += " /* ";
		query += marker;
		query += " */";
	} else {
		char buf[256];
		snprintf(buf, sizeof(buf), "SELECT pg_sleep(%d), '%s'", sleep_secs, marker);
		query = buf;
	}

	PGresult* res = nullptr;
	KillResult out = run_with_kill(marker_str, [cli, &query, &res]() { res = PQexec(cli, query.c_str()); });
	out.pgresult = res;
	return out;
}

// Fill `n` TAP slots with failures when a case aborts early, so plan() stays
// accurate. TAP infra counts "N tests planned but only M run" as failure, so
// this helper lets us bail out of a case without desyncing the plan.
static void emit_fail_fill(int n, const char* reason) {
	for (int i = 0; i < n; ++i) {
		ok(0, "SKIPPED: %s", reason);
	}
}

// --------------------------------------------------------------------------
// Sub-tests. Each is a helper that runs on a fresh PGconn and reports pass/fail
// via ok(). Counter deltas are exact (==), not >=: if the test environment is
// isolated per-group (which legacy-g2 is), exact is stronger.
// --------------------------------------------------------------------------

// Case A: full ROLLBACK recovery path, including NoticeResponse inspection,
// exact counter deltas, and the severity/sqlstate assertions on the
// synthesized ErrorResponse.
static void case_A_rollback_recovery() {
	Counters before = read_counters();

	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password, "ProxySQL");
	if (!cli) {
		ok(0, "case A: connect to ProxySQL");
		emit_fail_fill(10, "case A: aborted on connect");
		return;
	}
	NoticeBag bag;
	PQsetNoticeReceiver(cli, notice_receiver_cb, &bag);

	PGresult* r = PQexec(cli, "BEGIN");
	ok(PQresultStatus(r) == PGRES_COMMAND_OK,
	   "case A: BEGIN succeeded (%s)", PQresStatus(PQresultStatus(r)));
	PQclear(r);

	KillResult kr = run_poisoning_query(cli, nullptr);
	if (!kr.kill_delivered) {
		ok(0, "case A: killer thread failed to deliver pg_terminate_backend — aborting case");
		emit_fail_fill(9, "case A: aborted because kill did not fire");
		PQclear(kr.pgresult);
		PQfinish(cli);
		return;
	}
	diag("case A: killed victim backend pid=%d", kr.victim_pid);

	ExecStatusType st = PQresultStatus(kr.pgresult);
	const char* sqlstate = PQresultErrorField(kr.pgresult, PG_DIAG_SQLSTATE);
	const char* severity = PQresultErrorField(kr.pgresult, PG_DIAG_SEVERITY);
	ok(st == PGRES_FATAL_ERROR
	   && sqlstate && strcmp(sqlstate, "25P02") == 0
	   && severity && strcmp(severity, "ERROR") == 0,
	   "case A: ErrorResponse severity=ERROR sqlstate=25P02 (got status=%s, severity=%s, sqlstate=%s)",
	   PQresStatus(st), severity ?: "(none)", sqlstate ?: "(none)");
	PQclear(kr.pgresult);

	// Inspect the NoticeResponse the poison helper sent alongside the error.
	// Expect: exactly one notice with severity=WARNING, sqlstate=01000
	// (ERRCODE_WARNING), and a non-empty message body. Explicitly assert that
	// the sqlstate is NOT 57P01 — per design, the backend's original SQLSTATE
	// must not leak to the client. Also assert it's not 00000 which would
	// regress to the earlier buggy code path.
	bool notice_ok = false;
	for (const auto& n : bag.items) {
		if (n.severity == "WARNING" && n.sqlstate == "01000" && !n.message.empty()) {
			notice_ok = true;
			break;
		}
	}
	ok(notice_ok,
	   "case A: NoticeResponse has severity=WARNING sqlstate=01000 with non-empty message "
	   "(got %zu notices)", bag.items.size());
	bool no_57P01_in_notices = true;
	for (const auto& n : bag.items) {
		if (n.sqlstate == "57P01" || n.sqlstate == "00000") {
			no_57P01_in_notices = false;
			break;
		}
	}
	ok(no_57P01_in_notices,
	   "case A: no notice carries the backend's original 57P01 or the wrong 00000");

	ok(PQstatus(cli) == CONNECTION_OK,
	   "case A: client stays CONNECTION_OK");
	ok(PQtransactionStatus(cli) == PQTRANS_INERROR,
	   "case A: client tx status is PQTRANS_INERROR");

	// Statements that must be REJECTED while poisoned (stay in INERROR, get 25P02):
	const char* reject_cases[] = {
		"SELECT 42",                             // ordinary statement
		"RELEASE SAVEPOINT nonexistent",         // PG native: reject 25P02
		"ROLLBACK TO SAVEPOINT foo",             // we can't honor partial rollback on dead backend
		"ROLLBACK AND CHAIN",                    // we can't open a new tx on dead backend
		"ROLLBACK; SELECT 1;",                   // multi-statement: we'd silently drop SELECT 1
		"ROLLBACKET",                            // word-boundary: must not match ROLLBACK
	};
	int reject_passes = 0;
	for (const char* q : reject_cases) {
		r = PQexec(cli, q);
		const char* rej_sqlstate = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		bool ok_reject = PQresultStatus(r) == PGRES_FATAL_ERROR
			&& rej_sqlstate && strcmp(rej_sqlstate, "25P02") == 0
			&& PQtransactionStatus(cli) == PQTRANS_INERROR;
		if (ok_reject) reject_passes++;
		else diag("case A reject mismatch for '%s': status=%s sqlstate=%s txn=%d",
		          q, PQresStatus(PQresultStatus(r)), rej_sqlstate ?: "(none)",
		          (int)PQtransactionStatus(cli));
		PQclear(r);
	}
	ok(reject_passes == (int)(sizeof(reject_cases)/sizeof(*reject_cases)),
	   "case A: all %zu reject-while-poisoned variants returned 25P02 and stayed INERROR (got %d/%zu passing)",
	   sizeof(reject_cases)/sizeof(*reject_cases),
	   reject_passes, sizeof(reject_cases)/sizeof(*reject_cases));

	// Recover with a plain ROLLBACK WORK (verifies noise-word acceptance).
	r = PQexec(cli, "ROLLBACK WORK");
	ExecStatusType rst = PQresultStatus(r);
	ok(rst == PGRES_COMMAND_OK && PQtransactionStatus(cli) == PQTRANS_IDLE,
	   "case A: ROLLBACK WORK recovers poisoned session (status=%s, txn=%d)",
	   PQresStatus(rst), (int)PQtransactionStatus(cli));
	PQclear(r);

	// Post-recovery query succeeds and hits a NEW backend (different pid).
	r = PQexec(cli, "SELECT 1");
	ok(PQresultStatus(r) == PGRES_TUPLES_OK,
	   "case A: post-recovery SELECT 1 -> TUPLES_OK");
	PQclear(r);

	// Verify we're on a different backend: scan pg_stat_activity for a backend
	// whose application_name or query matches OUR session; since we can't tag
	// ourselves cheaply, we instead verify kr.victim_pid is NOT in the active
	// set. That's a sufficient condition: the old pid is dead, a new backend
	// was acquired.
	{
		PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
		                           cl.pgsql_server_username, cl.pgsql_server_password,
		                           "PG-direct (check post-recovery backend)");
		bool victim_gone = true;
		if (direct) {
			char q[128];
			snprintf(q, sizeof(q),
			         "SELECT COUNT(*) FROM pg_stat_activity WHERE pid = %d", kr.victim_pid);
			PGresult* rr = PQexec(direct, q);
			if (PQresultStatus(rr) == PGRES_TUPLES_OK && PQntuples(rr) == 1) {
				victim_gone = (atoi(PQgetvalue(rr, 0, 0)) == 0);
			}
			PQclear(rr);
			PQfinish(direct);
		}
		ok(victim_gone,
		   "case A: victim backend pid=%d is no longer in pg_stat_activity (fresh backend acquired)",
		   kr.victim_pid);
	}

	PQfinish(cli);

	// Exact counter deltas. Expected:
	//   total     = before + 1     (one poison event)
	//   recovered = before + 1     (ROLLBACK cleared it)
	//   rejected  = before + N     where N = number of reject_cases (6)
	Counters after = read_counters();
	diag("case A counters: total %lld->%lld , recovered %lld->%lld , rejected %lld->%lld",
	     before.total, after.total, before.recovered, after.recovered,
	     before.rejected, after.rejected);
	const int expected_rejected = (int)(sizeof(reject_cases)/sizeof(*reject_cases));
	ok(after.total == before.total + 1
	   && after.recovered == before.recovered + 1
	   && after.rejected == before.rejected + expected_rejected,
	   "case A: counter deltas exactly (+1 total, +1 recovered, +%d rejected)",
	   expected_rejected);
}

// Case B: COMMIT-on-poisoned recovers with the ROLLBACK tag and no notice, like PG native.
static void case_B_commit_recovery() {
	Counters before = read_counters();

	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password, "ProxySQL");
	if (!cli) { ok(0, "case B: connect"); emit_fail_fill(2, "case B aborted on connect"); return; }
	NoticeBag bag;
	PQsetNoticeReceiver(cli, notice_receiver_cb, &bag);

	PGresult* r = PQexec(cli, "BEGIN");
	PQclear(r);

	KillResult kr = run_poisoning_query(cli, nullptr);
	if (!kr.kill_delivered) {
		ok(0, "case B: killer failed to deliver kill — aborting");
		emit_fail_fill(2, "case B aborted on kill-not-delivered");
		PQclear(kr.pgresult);
		PQfinish(cli);
		return;
	}
	PQclear(kr.pgresult);

	// Clear any notices from the poison itself so we can specifically inspect
	// the one emitted by COMMIT-on-poisoned.
	size_t notices_before_commit = bag.items.size();

	r = PQexec(cli, "COMMIT");
	ExecStatusType st = PQresultStatus(r);
	const char* cmd_tag = PQcmdStatus(r);
	bool commit_recovers = (st == PGRES_COMMAND_OK)
		&& cmd_tag && (strcmp(cmd_tag, "ROLLBACK") == 0)
		&& PQtransactionStatus(cli) == PQTRANS_IDLE;
	ok(commit_recovers,
	   "case B: COMMIT inside poisoned tx returns ROLLBACK command tag + PQTRANS_IDLE (status=%s cmd=%s txn=%d)",
	   PQresStatus(st), cmd_tag ?: "(null)", (int)PQtransactionStatus(cli));
	PQclear(r);

	// PostgreSQL turns a COMMIT in an aborted transaction into a silent rollback. Its
	// "there is no transaction in progress" warning (25P01) is only for a COMMIT outside
	// any transaction, so no notice may follow the COMMIT here.
	std::string commit_notices;
	for (size_t i = notices_before_commit; i < bag.items.size(); ++i) {
		commit_notices += bag.items[i].sqlstate + " ";
	}
	ok(commit_notices.empty(),
	   "case B: COMMIT-on-poisoned emits no notice, as PostgreSQL does (notices after the COMMIT: '%s')",
	   commit_notices.c_str());

	PQfinish(cli);

	Counters after = read_counters();
	ok(after.total == before.total + 1
	   && after.recovered == before.recovered + 1
	   && after.rejected == before.rejected,
	   "case B: counter deltas exactly (+1 total, +1 recovered, +0 rejected)");
}

// Case C: autocommit statement killed mid-flight does NOT trigger poison.
// This is the security/correctness fix: we gate on is_in_transaction() rather
// than IsActiveTransaction() (which goes true via the disconnect heuristic).
// Pre-fix, this scenario would have bumped pgsql_tx_poisoned_total and
// synthesized a misleading "current transaction is aborted" error for a
// statement that was never in a transaction.
static void case_C_autocommit_no_poison() {
	Counters before = read_counters();

	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password, "ProxySQL");
	if (!cli) { ok(0, "case C: connect"); return; }

	// No BEGIN. Autocommit SELECT pg_sleep(), killed mid-flight.
	KillResult kr = run_poisoning_query(cli, nullptr);
	if (!kr.kill_delivered) {
		ok(0, "case C: killer failed to deliver kill — aborting");
		PQclear(kr.pgresult);
		PQfinish(cli);
		return;
	}
	// case C has exactly 1 ok() when the kill succeeds, so no emit_fail_fill
	// needed on the abort-before-kill paths above (that one ok(0) covers it).
	// The PQresult may be FATAL_ERROR with either 57P01 (forwarded), some
	// connection-broken code, or possibly just CONNECTION_BAD. We don't assert
	// a specific shape here — the invariant is that the feature MUST NOT
	// engage (no counter bump).
	PQclear(kr.pgresult);
	PQfinish(cli);

	Counters after = read_counters();
	diag("case C counters: total %lld->%lld , recovered %lld->%lld , rejected %lld->%lld",
	     before.total, after.total, before.recovered, after.recovered,
	     before.rejected, after.rejected);
	ok(after.total == before.total
	   && after.recovered == before.recovered
	   && after.rejected == before.rejected,
	   "case C: autocommit kill does NOT increment any tx-poisoned counter "
	   "(feature correctly gated on is_in_transaction())");
}

// Case D: with admin var off, mid-tx backend kill terminates the client
// session (pre-feature fallback), and none of the counters move.
static void case_D_admin_off() {
	if (!set_admin_bool("preserve_client_on_broken_backend_in_tx", false)) {
		ok(0, "case D: failed to set admin var to false — aborting");
		emit_fail_fill(1, "case D aborted on admin set false");
		return;
	}

	Counters before = read_counters();

	PGconn* cli = open_conn(cl.pgsql_host, cl.pgsql_port,
	                        cl.pgsql_username, cl.pgsql_password, "ProxySQL");
	if (!cli) {
		ok(0, "case D: connect");
		emit_fail_fill(1, "case D aborted on connect");
		return; // RAII guard restores admin var on scope exit
	}

	PGresult* r = PQexec(cli, "BEGIN");
	PQclear(r);

	KillResult kr = run_poisoning_query(cli, nullptr);
	if (!kr.kill_delivered) {
		ok(0, "case D: killer failed to deliver kill — aborting");
		emit_fail_fill(1, "case D aborted on kill-not-delivered");
		PQclear(kr.pgresult);
		PQfinish(cli);
		return;
	}
	PQclear(kr.pgresult);

	// Expected pre-feature behavior: client session torn down.
	bool terminated = (PQstatus(cli) != CONNECTION_OK);
	if (!terminated) {
		PGresult* ping = PQexec(cli, "SELECT 1");
		terminated = (PQresultStatus(ping) != PGRES_TUPLES_OK)
			|| (PQstatus(cli) != CONNECTION_OK);
		PQclear(ping);
	}
	ok(terminated,
	   "case D: admin var off → mid-tx backend kill terminates client session");
	PQfinish(cli);

	// Counters must NOT move when the feature is off.
	Counters after = read_counters();
	ok(after.total == before.total
	   && after.recovered == before.recovered
	   && after.rejected == before.rejected,
	   "case D: admin-off → no tx-poisoned counter moved (total %lld->%lld, recovered %lld->%lld, rejected %lld->%lld)",
	   before.total, after.total, before.recovered, after.recovered, before.rejected, after.rejected);
}

// --------------------------------------------------------------------------
// Case E: a COMMIT whose backend dies before answering is never reported as
// aborted. The backend can die after the commit is durable, so the outcome is
// unknown: the client must be disconnected, as PostgreSQL itself would leave it,
// not told 25P02 and invited to run the work again. The COMMIT is held in flight
// by a deferred constraint trigger that sleeps; killing the backend there needs
// no server-wide setting. Run once per backend protocol.
// --------------------------------------------------------------------------

static const int BACKEND_HG = 0;
static const int CASE_E_CHECKS = 9;

static PGconn* open_admin() {
	return open_conn(cl.pgsql_admin_host, cl.pgsql_admin_port,
	                 cl.admin_username, cl.admin_password, "ProxySQL admin (PgSQL protocol)");
}

static PGconn* open_proxy() {
	return open_conn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, "ProxySQL",
	                 g_client_tls ? "require" : "disable");
}

static bool exec_ok(PGconn* c, const std::string& sql) {
	PGresult* r = PQexec(c, sql.c_str());
	const bool ok_ = PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK;
	if (!ok_) diag("'%s' failed: %s", sql.c_str(), PQerrorMessage(c));
	PQclear(r);
	return ok_;
}

static bool is_sqlstate(const PGresult* r, const char* code) {
	const char* s = r ? PQresultErrorField(r, PG_DIAG_SQLSTATE) : nullptr;
	return s && strcmp(s, code) == 0;
}

// The SQLSTATE a request was answered with ("" for none, as when the connection is lost).
static std::string answer_sqlstate(PGresult* r) {
	const char* s = r ? PQresultErrorField(r, PG_DIAG_SQLSTATE) : nullptr;
	std::string out = s ? s : "";
	PQclear(r);
	return out;
}

// The backend server rows as INSERTs recreating every column, so re-inserting them drops every
// pooled backend connection: a pooled one keeps the protocol it was opened with.
static std::vector<std::string> read_servers(PGconn* admin) {
	std::vector<std::string> rows;
	PGresult* res = PQexec(admin, ("SELECT * FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(BACKEND_HG)).c_str());
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
	}
	PQclear(res);
	return rows;
}

static bool flush_backend_pool(PGconn* admin, const std::vector<std::string>& saved) {
	if (saved.empty()) return false;
	if (!exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(BACKEND_HG))) return false;
	if (!exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	for (const auto& ins : saved) {
		if (!exec_ok(admin, ins)) return false;
	}
	if (!exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
	usleep(200000);
	return true;
}

// A table whose rows hold COMMIT (and PREPARE TRANSACTION) in a deferred trigger that sleeps,
// and a plain one. Made through ProxySQL so the test user owns them.
static bool create_commit_fixtures() {
	PGconn* c = open_proxy();
	if (!c) return false;
	const bool made =
		exec_ok(c, "DROP TABLE IF EXISTS txp_commit_slow") &&
		exec_ok(c, "DROP TABLE IF EXISTS txp_commit_plain") &&
		exec_ok(c, "CREATE TABLE txp_commit_slow (id text)") &&
		exec_ok(c, "CREATE TABLE txp_commit_plain (id text)") &&
		exec_ok(c, "CREATE OR REPLACE FUNCTION txp_commit_slow_trg() RETURNS trigger LANGUAGE plpgsql "
		           "AS $$ BEGIN PERFORM pg_sleep(5); RETURN NULL; END $$") &&
		exec_ok(c, "CREATE CONSTRAINT TRIGGER txp_commit_slow_t AFTER INSERT ON txp_commit_slow "
		           "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION txp_commit_slow_trg()");
	PQfinish(c);
	return made;
}

static void drop_commit_fixtures() {
	PGconn* c = open_proxy();
	if (!c) return;
	exec_ok(c, "DROP TABLE IF EXISTS txp_commit_slow");
	exec_ok(c, "DROP TABLE IF EXISTS txp_commit_plain");
	exec_ok(c, "DROP FUNCTION IF EXISTS txp_commit_slow_trg()");
	PQfinish(c);
	// A server with prepared transactions enabled keeps one if a kill missed it.
	PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
	                           cl.pgsql_server_username, cl.pgsql_server_password, "PG-direct (superuser)");
	if (!direct) return;
	PGresult* r = PQexec(direct, "SELECT 1 FROM pg_prepared_xacts WHERE gid = 'txp_commit_gid'");
	const bool left = PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1;
	PQclear(r);
	if (left) exec_ok(direct, "ROLLBACK PREPARED 'txp_commit_gid'");
	PQfinish(direct);
}

static long long count_plain_rows(const std::string& id) {
	PGconn* c = open_proxy();
	if (!c) return -1;
	const char* params[1] = { id.c_str() };
	PGresult* r = PQexecParams(c, "SELECT count(*) FROM txp_commit_plain WHERE id = $1", 1, nullptr, params, nullptr, nullptr, 0);
	long long n = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? atoll(PQgetvalue(r, 0, 0)) : -1;
	PQclear(r);
	PQfinish(c);
	return n;
}

struct PipeResult {
	ExecStatusType status;
	std::string sqlstate;
	std::string cmd;
};

// Sends the statements as one pipeline ending in a single Sync and collects every result,
// stopping at the Sync or when the connection is lost.
static std::vector<PipeResult> run_pipeline(PGconn* cli, const std::vector<std::string>& stmts) {
	std::vector<PipeResult> out;
	if (PQenterPipelineMode(cli) != 1) return out;
	for (const auto& s : stmts) PQsendQueryParams(cli, s.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
	PQpipelineSync(cli);
	for (int nulls = 0; nulls < 64; ) {
		PGresult* r = PQgetResult(cli);
		if (r == nullptr) {
			if (PQstatus(cli) != CONNECTION_OK) break;
			nulls++;
			continue;
		}
		const ExecStatusType st = PQresultStatus(r);
		if (st == PGRES_PIPELINE_SYNC) { PQclear(r); break; }
		const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
		out.push_back({ st, s ? s : "", PQcmdStatus(r) ? PQcmdStatus(r) : "" });
		PQclear(r);
		if (PQstatus(cli) != CONNECTION_OK) break;
	}
	if (PQstatus(cli) == CONNECTION_OK) PQexitPipelineMode(cli);
	return out;
}

// Opens a session inside a transaction whose COMMIT will run the sleeping trigger.
static PGconn* begin_slow_commit_txn(const char* row) {
	PGconn* cli = open_proxy();
	if (!cli) return nullptr;
	if (!exec_ok(cli, "BEGIN") ||
	    !exec_ok(cli, std::string("INSERT INTO txp_commit_slow VALUES ('") + row + "')")) {
		PQfinish(cli);
		return nullptr;
	}
	return cli;
}

// One COMMIT-like request killed in flight: the client must be disconnected and must not be
// told 25P02. send() returns the SQLSTATE the request was answered with.
template <typename F>
static void check_commit_disconnects(const char* mode, const char* label, F send) {
	PGconn* cli = begin_slow_commit_txn(label);
	if (!cli) { ok(0, "case E [%s] %s: setup failed", mode, label); return; }
	const std::string marker = new_marker();
	std::string answer;
	KillResult kr = run_with_kill(marker, [&]() { answer = send(cli, marker); });
	const bool disconnected = PQstatus(cli) != CONNECTION_OK;
	ok(kr.kill_delivered && disconnected && answer != "25P02",
	   "case E [%s] %s killed in flight: client disconnected, not told 25P02 (kill=%d, connection=%s, sqlstate=%s)",
	   mode, label, kr.kill_delivered, disconnected ? "lost" : "OK", answer.empty() ? "(none)" : answer.c_str());
	PQfinish(cli);
}

static void case_E_unanswered_commit(const char* mode) {
	// COMMIT over the simple protocol.
	check_commit_disconnects(mode, "COMMIT", [](PGconn* c, const std::string& m) {
		return answer_sqlstate(PQexec(c, ("COMMIT /* " + m + " */").c_str()));
	});
	// PREPARE TRANSACTION makes the work durable too. Its deferred triggers run before the
	// server checks max_prepared_transactions, so this holds where prepared transactions are off.
	check_commit_disconnects(mode, "PREPARE TRANSACTION", [](PGconn* c, const std::string& m) {
		return answer_sqlstate(PQexec(c, ("PREPARE TRANSACTION 'txp_commit_gid' /* " + m + " */").c_str()));
	});
	// A COMMIT that is not the first statement of the query.
	check_commit_disconnects(mode, "INSERT; COMMIT", [](PGconn* c, const std::string& m) {
		return answer_sqlstate(PQexec(c, ("INSERT INTO txp_commit_plain VALUES ('multi'); COMMIT /* " + m + " */").c_str()));
	});
	// COMMIT over the extended protocol: a native connection sends it as a batch.
	check_commit_disconnects(mode, "extended COMMIT", [](PGconn* c, const std::string& m) {
		return answer_sqlstate(PQexecParams(c, ("COMMIT /* " + m + " */").c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0));
	});
	// A COMMIT among several pipelined statements: 25P02 for any of them would be the poison.
	check_commit_disconnects(mode, "pipelined INSERT + COMMIT", [](PGconn* c, const std::string& m) {
		for (const auto& r : run_pipeline(c, { "INSERT INTO txp_commit_plain VALUES ('pipelined')", "COMMIT /* " + m + " */" })) {
			if (r.sqlstate == "25P02") return r.sqlstate;
		}
		return std::string();
	});

	// A COMMIT the backend confirmed, then a later statement of the same pipeline killed. A native
	// connection holds the batch's replies until it ends: the client must still learn that the
	// COMMIT succeeded, or be disconnected, never be answered 25P02 for it.
	{
		const std::string confirmed = std::string("confirmed_") + mode;
		const std::string lost = std::string("lost_") + mode;
		PGconn* cli = open_proxy();
		const bool setup = cli && exec_ok(cli, "BEGIN") &&
			exec_ok(cli, "INSERT INTO txp_commit_plain VALUES ('" + confirmed + "')");
		if (!setup) {
			ok(0, "case E [%s] confirmed COMMIT then killed statement: setup failed", mode);
			emit_fail_fill(1, "case E confirmed COMMIT setup failed");
		} else {
			const std::string marker = new_marker();
			std::vector<PipeResult> res;
			KillResult kr = run_with_kill(marker, [&]() {
				res = run_pipeline(cli, {
					"COMMIT", "BEGIN",
					"INSERT INTO txp_commit_plain VALUES ('" + lost + "')",
					"SELECT pg_sleep(5), '" + marker + "'" });
			});
			const bool commit_ok = !res.empty() && res[0].status == PGRES_COMMAND_OK && res[0].cmd == "COMMIT";
			const bool commit_aborted = !res.empty() && res[0].sqlstate == "25P02";
			const bool disconnected = PQstatus(cli) != CONNECTION_OK;
			ok(kr.kill_delivered && (commit_ok || (disconnected && !commit_aborted)),
			   "case E [%s] confirmed COMMIT then killed statement: COMMIT %s, connection %s (kill=%d)",
			   mode, commit_ok ? "reported OK" : (commit_aborted ? "answered 25P02" : "unanswered"),
			   disconnected ? "lost" : "OK", kr.kill_delivered);
			ok(count_plain_rows(confirmed) == 1 && count_plain_rows(lost) == 0,
			   "case E [%s] confirmed COMMIT then killed statement: the committed row is there, the later one is not",
			   mode);
		}
		if (cli) PQfinish(cli);
	}

	// Controls: without a COMMIT in flight the session is still poisoned. A pipeline, and an SQL
	// PREPARE, which only creates a statement.
	{
		PGconn* cli = open_proxy();
		bool poisoned = false;
		bool killed = false;
		if (cli && exec_ok(cli, "BEGIN")) {
			const std::string marker = new_marker();
			std::vector<PipeResult> res;
			KillResult kr = run_with_kill(marker, [&]() {
				res = run_pipeline(cli, {
					"INSERT INTO txp_commit_plain VALUES ('control')",
					"SELECT pg_sleep(5), '" + marker + "'" });
			});
			killed = kr.kill_delivered;
			for (const auto& r : res) poisoned = poisoned || r.sqlstate == "25P02";
			poisoned = poisoned && PQstatus(cli) == CONNECTION_OK;
			if (PQstatus(cli) == CONNECTION_OK) exec_ok(cli, "ROLLBACK");
		}
		ok(killed && poisoned, "case E [%s] pipeline without a COMMIT: still poisoned (25P02, connection kept)", mode);
		if (cli) PQfinish(cli);
	}
	{
		PGconn* cli = open_proxy();
		bool poisoned = false;
		bool killed = false;
		if (cli && exec_ok(cli, "BEGIN")) {
			KillResult kr = run_poisoning_query(cli, "SELECT pg_sleep(5); PREPARE txp_commit_stmt AS SELECT 1");
			killed = kr.kill_delivered;
			poisoned = is_sqlstate(kr.pgresult, "25P02") && PQstatus(cli) == CONNECTION_OK;
			PQclear(kr.pgresult);
			if (PQstatus(cli) == CONNECTION_OK) exec_ok(cli, "ROLLBACK");
		}
		ok(killed && poisoned, "case E [%s] SQL PREPARE in flight: still poisoned (25P02, connection kept)", mode);
		if (cli) PQfinish(cli);
	}
}

// --------------------------------------------------------------------------
// Case F: session state (a session advisory lock, a temp table, an SQL PREPARE, a WITH HOLD
// cursor, a temp sequence, LISTEN) dies with the backend. Poisoned, the client would go on as if
// it still existed, and another session can take its lock: it must be disconnected instead, as
// PostgreSQL would leave it. State a rollback ends anyway still poisons. Run once per protocol.
// --------------------------------------------------------------------------

static const int CASE_F_CHECKS = 16;

// Prepares a client for a case F check: SQL run before the BEGIN, the BEGIN, then SQL inside it.
typedef std::function<bool(PGconn*)> Prepare;

static Prepare sql_steps(std::vector<std::string> before_begin, std::vector<std::string> in_txn = {}) {
	return [before_begin, in_txn](PGconn* c) {
		bool ready = true;
		for (const auto& s : before_begin) ready = ready && exec_ok(c, s);
		ready = ready && exec_ok(c, "BEGIN");
		for (const auto& s : in_txn) ready = ready && exec_ok(c, s);
		return ready;
	};
}

// Runs `prepare`, kills the backend in a statement of the open transaction, and checks the client
// was disconnected (state that died with the backend) or poisoned (nothing was lost).
static void check_kill_in_txn(const char* mode, const char* label, bool expect_disconnect, const Prepare& prepare) {
	PGconn* cli = open_proxy();
	if (!cli || !prepare(cli)) {
		ok(0, "case F [%s] %s: setup failed", mode, label);
		if (cli) PQfinish(cli);
		return;
	}
	KillResult kr = run_poisoning_query(cli, nullptr);
	const bool alive = PQstatus(cli) == CONNECTION_OK;
	const std::string answer = answer_sqlstate(kr.pgresult);
	const bool as_expected = expect_disconnect ? (!alive && answer != "25P02") : (alive && answer == "25P02");
	ok(kr.kill_delivered && as_expected,
	   "case F [%s] %s, backend killed in a transaction: client %s (kill=%d, connection=%s, sqlstate=%s)",
	   mode, label, expect_disconnect ? "disconnected, not told 25P02" : "poisoned, connection kept",
	   kr.kill_delivered, alive ? "OK" : "lost", answer.empty() ? "(none)" : answer.c_str());
	if (alive) exec_ok(cli, "ROLLBACK");
	PQfinish(cli);
}

// A parameterised statement, sent over the extended protocol.
static bool exec_params_ok(PGconn* c, const char* sql, const char* param) {
	PGresult* r = PQexecParams(c, sql, 1, nullptr, &param, nullptr, nullptr, 0);
	const bool ok_ = PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK;
	if (!ok_) diag("'%s' failed: %s", sql, PQerrorMessage(c));
	PQclear(r);
	return ok_;
}

static void case_F_session_state(const char* mode, bool native) {
	auto dies = [mode](const char* label, std::vector<std::string> setup) {
		check_kill_in_txn(mode, label, true, sql_steps(std::move(setup)));
	};
	dies("session advisory lock", { "SELECT pg_advisory_lock(72510)" });
	dies("temp table", { "CREATE TEMP TABLE txp_f_tmp (x int)" });
	dies("SQL PREPARE", { "PREPARE txp_f_stmt AS SELECT 1" });
	dies("WITH HOLD cursor", { "BEGIN", "DECLARE txp_f_cur CURSOR WITH HOLD FOR SELECT 1", "COMMIT" });
	dies("temp sequence", { "CREATE TEMP SEQUENCE txp_f_seq" });
	// A libpq backend connection refuses LISTEN.
	if (native) {
		dies("LISTEN", { "LISTEN txp_f_channel" });
	} else {
		skip(1, "case F [%s] LISTEN: refused on a libpq backend connection", mode);
	}

	// Control: a savepoint and a transaction advisory lock end with the rollback anyway.
	check_kill_in_txn(mode, "savepoint + transaction advisory lock", false,
		sql_steps({}, { "SAVEPOINT txp_f_sp", "SELECT pg_advisory_xact_lock(72511)" }));

	// When the state is taken: in the transaction that is killed, in an earlier one that
	// committed, or over the extended protocol.
	check_kill_in_txn(mode, "advisory lock taken inside the killed transaction", true,
		sql_steps({}, { "SELECT pg_advisory_lock(72512)" }));
	dies("advisory lock taken in an earlier committed transaction",
		{ "BEGIN", "SELECT pg_advisory_lock(72513)", "COMMIT" });
	check_kill_in_txn(mode, "advisory lock taken over the extended protocol", true,
		[](PGconn* c) { return exec_params_ok(c, "SELECT pg_advisory_lock($1::bigint)", "72515") && exec_ok(c, "BEGIN"); });

	// A SET the proxy cannot replay on a new backend is lost too; one it tracks is not, so the
	// client is still poisoned and not disconnected for it.
	dies("untracked custom variable (SET)", { "SET txp_f.setting = 1" });
	check_kill_in_txn(mode, "tracked SET (search_path)", false, sql_steps({ "SET search_path TO public" }));

	// A multiplex=0 rule only says "do not share this connection"; no state is held, so the client
	// is still poisoned and not disconnected.
	check_kill_in_txn(mode, "multiplex=0 rule hit, no session state", false,
		sql_steps({ "SELECT 1 AS txp_f_mux_off" }));

	// Releasing the state makes the poison safe again.
	check_kill_in_txn(mode, "session advisory lock released with pg_advisory_unlock_all", false,
		sql_steps({ "SELECT pg_advisory_lock(72516)", "SELECT pg_advisory_unlock_all()" }));
	check_kill_in_txn(mode, "temp table dropped with DISCARD TEMP", false,
		sql_steps({ "CREATE TEMP TABLE txp_f_tmp2 (x int)", "DISCARD TEMP" }));
	check_kill_in_txn(mode, "WITH HOLD cursor closed with CLOSE ALL", false,
		sql_steps({ "BEGIN", "DECLARE txp_f_cur2 CURSOR WITH HOLD FOR SELECT 1", "COMMIT", "CLOSE ALL" }));
}

// --------------------------------------------------------------------------
// Case G: an error ProxySQL raises itself inside a transaction (a rejected DISCARD ALL, a query
// rule's error_msg) poisons the session while the backend is alive. The backend holds the client's
// session advisory lock, which PostgreSQL would keep: ending the poisoned transaction must roll it
// back, not drop the connection, and a COMMIT must not commit the work. Run once per protocol.
// --------------------------------------------------------------------------

static const int CASE_G_CHECKS = 9;
static const int RULE_G_ID = 7901;
static const int RULE_F_MUX_ID = 7902;
static const int RULE_G_HG_ID = 7903;
static const int HG_G = 1;

// The first value of a one-row result, "" on error.
static std::string scalar(PGconn* c, const std::string& sql) {
	PGresult* r = PQexec(c, sql.c_str());
	std::string out = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return out;
}

static bool fails(PGconn* c, const char* sql) {
	PGresult* r = PQexec(c, sql);
	const bool failed = PQresultStatus(r) == PGRES_FATAL_ERROR;
	PQclear(r);
	return failed;
}

// Takes advisory lock `key` (with pg_try_advisory_lock if `try_lock`), opens a transaction that inserts
// a row, provokes an error of ProxySQL's with `provoke`, ends the poisoned transaction with `end`. Then
// checks the row is gone and the session still holds the lock: pg_advisory_unlock answers true only for
// a lock the session holds.
static void check_lock_survives(const char* mode, const char* label, long key, bool try_lock,
                                const char* provoke, const std::function<bool(PGconn*)>& end,
                                const std::function<bool(PGconn*)>& after = nullptr) {
	PGconn* cli = open_proxy();
	const std::string k = std::to_string(key);
	bool ready = cli && exec_ok(cli, "CREATE TABLE IF NOT EXISTS txp_g_rows (x int)") &&
	             exec_ok(cli, "DELETE FROM txp_g_rows");
	ready = ready && (try_lock ? scalar(cli, "SELECT pg_try_advisory_lock(" + k + ")") == "t"
	                           : exec_ok(cli, "SELECT pg_advisory_lock(" + k + ")"));
	ready = ready && exec_ok(cli, "BEGIN") && exec_ok(cli, "INSERT INTO txp_g_rows VALUES (1)");
	if (!ready) {
		ok(0, "case G [%s] %s: setup failed", mode, label);
		if (cli) PQfinish(cli);
		return;
	}
	const bool provoked = fails(cli, provoke);
	const bool ended = end(cli) && (!after || after(cli));
	const bool alive = PQstatus(cli) == CONNECTION_OK;
	const bool kept_lock = alive && scalar(cli, "SELECT pg_advisory_unlock(" + k + ")") == "t";
	const bool rolled_back = alive && scalar(cli, "SELECT count(*) FROM txp_g_rows") == "0";
	ok(provoked && ended && alive && kept_lock && rolled_back,
	   "case G [%s] %s: session kept its advisory lock and the work was rolled back (error=%d, ended=%d, alive=%d, lock=%d, rows_gone=%d)",
	   mode, label, provoked, ended, alive, kept_lock, rolled_back);
	if (alive) exec_ok(cli, "DROP TABLE IF EXISTS txp_g_rows");
	if (cli) PQfinish(cli);
}

// A client may send its next statements without waiting for the answer to the ROLLBACK that ends a
// poisoned transaction. They must run after the rollback of the backend, not inside the transaction the
// client was told is over: the INSERT would be reported done, then thrown away with the old transaction.
// Timing decides whether they were read in the same batch, so the sequence is repeated.
static void check_pipelined_behind_rollback(const char* mode) {
	const char* label = "statements pipelined behind the ROLLBACK run after the rollback";
	const int rounds = 6;
	PGconn* cli = open_proxy();
	if (!cli || !exec_ok(cli, "CREATE TABLE IF NOT EXISTS txp_g_rows (x int)")) {
		ok(0, "case G [%s] %s: setup failed", mode, label);
		if (cli) PQfinish(cli);
		return;
	}
	int good = 0;
	for (int round = 0; round < rounds; round++) {
		bool ready = exec_ok(cli, "DELETE FROM txp_g_rows") && exec_ok(cli, "SELECT pg_advisory_lock(72608)") &&
		             exec_ok(cli, "BEGIN") && exec_ok(cli, "INSERT INTO txp_g_rows VALUES (1)");
		if (!ready || !fails(cli, "DISCARD ALL")) break;
		const char* stmts[] = { "ROLLBACK", "INSERT INTO txp_g_rows VALUES (2)", "COMMIT", "SELECT pg_advisory_unlock(72608)" };
		bool sent = PQenterPipelineMode(cli) == 1;
		for (const char* q : stmts) {
			sent = sent && PQsendQueryParams(cli, q, 0, nullptr, nullptr, nullptr, nullptr, 0) == 1 && PQpipelineSync(cli) == 1;
		}
		std::string unlocked;
		for (int syncs = 0; sent && syncs < 4;) {
			PGresult* r = PQgetResult(cli);
			if (r == nullptr) continue;
			if (PQresultStatus(r) == PGRES_PIPELINE_SYNC) syncs++;
			else if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) unlocked = PQgetvalue(r, 0, 0);
			PQclear(r);
		}
		while (sent && PQgetResult(cli) != nullptr) {}
		PQexitPipelineMode(cli);
		// Only the INSERT after the ROLLBACK is committed; the one inside the old transaction is not.
		if (sent && unlocked == "t" && scalar(cli, "SELECT coalesce(string_agg(x::text, ',' ORDER BY x), 'none') FROM txp_g_rows") == "2") good++;
	}
	ok(good == rounds, "case G [%s] %s (%d of %d rounds right)", mode, label, good, rounds);
	if (PQstatus(cli) == CONNECTION_OK) exec_ok(cli, "DROP TABLE IF EXISTS txp_g_rows");
	PQfinish(cli);
}

// A Simple Query message as raw bytes: libpq cannot send a second one before the first is answered.
static std::string simple_query_msg(const std::string& sql) {
	std::string m(1, 'Q');
	const uint32_t len = htonl((uint32_t)(sql.size() + 5));
	m.append((const char*)&len, 4);
	m += sql;
	m.push_back('\0');
	return m;
}

// The connection's own TLS session, if it has one: raw bytes must go through it.
static SSL* conn_ssl(PGconn* c) { return PQsslInUse(c) ? (SSL*)PQgetssl(c) : nullptr; }

static bool send_raw(PGconn* c, const std::string& wire) {
	SSL* ssl = conn_ssl(c);
	size_t off = 0;
	while (off < wire.size()) {
		const ssize_t n = ssl ? SSL_write(ssl, wire.data() + off, (int)(wire.size() - off))
		                      : send(PQsocket(c), wire.data() + off, wire.size() - off, 0);
		if (n <= 0) return false;
		off += (size_t)n;
	}
	return true;
}

// Reads backend messages straight off the socket until `ready` ReadyForQuery have arrived. The value of
// the first column of the last DataRow goes to *last_value. Only for a connection with nothing pending.
static bool read_raw_until_ready(PGconn* c, int ready, std::string* last_value) {
	const int fd = PQsocket(c);
	std::string buf;
	while (ready > 0) {
		while (buf.size() >= 5 && ready > 0) {
			uint32_t len;
			memcpy(&len, buf.data() + 1, 4);
			len = ntohl(len);
			if (buf.size() < 1 + (size_t)len) break;
			if (buf[0] == 'D' && len >= 10) {
				int32_t vlen;
				memcpy(&vlen, buf.data() + 7, 4);
				vlen = (int32_t)ntohl((uint32_t)vlen);
				if (vlen >= 0 && (size_t)vlen + 11 <= 1 + (size_t)len) last_value->assign(buf.data() + 11, vlen);
			}
			if (buf[0] == 'Z') ready--;
			buf.erase(0, 1 + (size_t)len);
		}
		if (ready == 0) break;
		SSL* ssl = conn_ssl(c);
		// Bytes TLS has already decrypted are not on the socket any more.
		struct pollfd pfd = { fd, POLLIN, 0 };
		if (!(ssl && SSL_pending(ssl) > 0) && poll(&pfd, 1, 10000) <= 0) return false;
		char tmp[4096];
		const ssize_t n = ssl ? SSL_read(ssl, tmp, sizeof(tmp)) : recv(fd, tmp, sizeof(tmp), 0);
		if (n <= 0) return false;
		buf.append(tmp, (size_t)n);
	}
	return true;
}

// The same as check_pipelined_behind_rollback(), over the simple protocol: four Simple Queries in one write.
static void check_simple_pipelined_behind_rollback(const char* mode) {
	const char* label = "simple queries pipelined behind the ROLLBACK run after the rollback";
	const int rounds = 6;
	PGconn* cli = open_proxy();
	if (!cli || !exec_ok(cli, "CREATE TABLE IF NOT EXISTS txp_g_rows (x int)")) {
		ok(0, "case G [%s] %s: setup failed", mode, label);
		if (cli) PQfinish(cli);
		return;
	}
	int good = 0;
	for (int round = 0; round < rounds; round++) {
		bool ready = exec_ok(cli, "DELETE FROM txp_g_rows") && exec_ok(cli, "SELECT pg_advisory_lock(72609)") &&
		             exec_ok(cli, "BEGIN") && exec_ok(cli, "INSERT INTO txp_g_rows VALUES (1)");
		if (!ready || !fails(cli, "DISCARD ALL")) break;
		const std::string wire = simple_query_msg("ROLLBACK") + simple_query_msg("INSERT INTO txp_g_rows VALUES (2)") +
		                         simple_query_msg("COMMIT") + simple_query_msg("SELECT pg_advisory_unlock(72609)");
		std::string unlocked;
		const bool sent = send_raw(cli, wire) && read_raw_until_ready(cli, 4, &unlocked);
		if (!sent) break;
		if (unlocked == "t" && scalar(cli, "SELECT coalesce(string_agg(x::text, ',' ORDER BY x), 'none') FROM txp_g_rows") == "2") good++;
	}
	ok(good == rounds, "case G [%s] %s (%d of %d rounds right)", mode, label, good, rounds);
	if (PQstatus(cli) == CONNECTION_OK) exec_ok(cli, "DROP TABLE IF EXISTS txp_g_rows");
	PQfinish(cli);
}

// SET values changed in the poisoned transaction are put back by the rollback, on the proxy and on the backend.
static void check_set_values_after_rollback(const char* mode) {
	const char* label = "SET values changed in the transaction are back after the rollback";
	PGconn* cli = open_proxy();
	std::string sp0, wm0;
	bool ready = cli && exec_ok(cli, "SET search_path TO public") && exec_ok(cli, "SELECT pg_advisory_lock(72606)");
	if (ready) { sp0 = scalar(cli, "SHOW search_path"); wm0 = scalar(cli, "SHOW work_mem"); }
	ready = ready && !sp0.empty() && !wm0.empty() && exec_ok(cli, "BEGIN") &&
	        exec_ok(cli, "SET search_path TO pg_catalog") && exec_ok(cli, "SET work_mem = '9MB'");
	if (!ready) {
		ok(0, "case G [%s] %s: setup failed", mode, label);
		if (cli) PQfinish(cli);
		return;
	}
	const bool provoked = fails(cli, "DISCARD ALL");
	const bool ended = exec_ok(cli, "ROLLBACK");
	const std::string sp1 = scalar(cli, "SHOW search_path"), wm1 = scalar(cli, "SHOW work_mem");
	const bool kept_lock = scalar(cli, "SELECT pg_advisory_unlock(72606)") == "t";
	ok(provoked && ended && sp1 == sp0 && wm1 == wm0 && kept_lock,
	   "case G [%s] %s (search_path '%s' -> '%s', work_mem '%s' -> '%s', lock=%d)",
	   mode, label, sp0.c_str(), sp1.c_str(), wm0.c_str(), wm1.c_str(), kept_lock);
	PQfinish(cli);
}

static void case_G_local_error_keeps_session_state(const char* mode, PGconn* admin) {
	auto simple = [](const char* sql) { return [sql](PGconn* c) { return exec_ok(c, sql); }; };
	auto extended = [](const char* sql) {
		return [sql](PGconn* c) {
			PGresult* r = PQexecParams(c, sql, 0, nullptr, nullptr, nullptr, nullptr, 0);
			const bool ok_ = PQresultStatus(r) == PGRES_COMMAND_OK;
			PQclear(r);
			return ok_;
		};
	};
	check_lock_survives(mode, "rejected DISCARD ALL, ended by ROLLBACK", 72601, false, "DISCARD ALL", simple("ROLLBACK"));
	check_lock_survives(mode, "rejected DISCARD ALL, ended by COMMIT", 72602, false, "DISCARD ALL", simple("COMMIT"));
	check_lock_survives(mode, "query rule error, ended by ROLLBACK over the extended protocol", 72603, false,
	                    "SELECT 1 AS txp_g_blocked", extended("ROLLBACK"));
	check_lock_survives(mode, "query rule error, ended by COMMIT", 72604, false, "SELECT 1 AS txp_g_blocked", simple("COMMIT"));
	check_lock_survives(mode, "lock taken with pg_try_advisory_lock", 72605, true, "DISCARD ALL", simple("ROLLBACK"));
	check_set_values_after_rollback(mode);
	check_pipelined_behind_rollback(mode);
	check_simple_pipelined_behind_rollback(mode);

	// The next statement goes to another hostgroup: the rollback must not wait for it, or a COMMIT would
	// find the abandoned transaction still open on the first hostgroup and commit its work.
	const bool hg_ok =
		exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id = " + std::to_string(HG_G)) &&
		exec_ok(admin, "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, use_ssl) SELECT " + std::to_string(HG_G) +
			", hostname, port, use_ssl FROM pgsql_servers WHERE hostgroup_id = " + std::to_string(BACKEND_HG) + " LIMIT 1") &&
		exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME") &&
		exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id = " + std::to_string(RULE_G_HG_ID)) &&
		exec_ok(admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (" +
			std::to_string(RULE_G_HG_ID) + ", 1, 'txp_g_hg', " + std::to_string(HG_G) + ", 1)") &&
		exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	if (hg_ok) {
		check_lock_survives(mode, "next statement on another hostgroup, then a stray COMMIT", 72607, false,
		                    "DISCARD ALL", simple("ROLLBACK"),
		                    [](PGconn* c) { return exec_ok(c, "SELECT 1 AS txp_g_hg") && exec_ok(c, "COMMIT"); });
	} else {
		ok(0, "case G [%s] another hostgroup: cannot set up the second hostgroup", mode);
	}
	exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id = " + std::to_string(RULE_G_HG_ID));
	exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	exec_ok(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id = " + std::to_string(HG_G));
	exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

// Whether the backend leg of a proxy session is TLS, as PostgreSQL itself sees it: "true", "false", or ""
// if it could not be told.
static std::string backend_leg_tls() {
	PGconn* cli = open_proxy();
	if (!cli) return "";
	const std::string marker = new_marker();
	std::string seen;
	std::thread watcher([&seen, &marker]() {
		PGconn* direct = open_conn(cl.pgsql_server_host, cl.pgsql_server_port,
		                           cl.pgsql_server_username, cl.pgsql_server_password, "PG-direct (superuser)");
		if (!direct) return;
		const char* params[1] = { marker.c_str() };
		for (int i = 0; i < 40 && seen.empty(); i++) {
			PGresult* r = PQexecParams(direct,
				"SELECT coalesce(s.ssl::text, '') FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s USING (pid) "
				"WHERE a.state = 'active' AND a.query LIKE '%' || $1 || '%' AND a.pid <> pg_backend_pid()",
				1, nullptr, params, nullptr, nullptr, 0);
			if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) seen = PQgetvalue(r, 0, 0);
			PQclear(r);
			if (seen.empty()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		PQfinish(direct);
	});
	PQclear(PQexec(cli, ("SELECT pg_sleep(2), '" + marker + "'").c_str()));
	watcher.join();
	PQfinish(cli);
	return seen;
}

// Cases F and G run in four variants per backend protocol: the client talks TLS to the proxy or not, and
// the proxy talks TLS to the backend or not. Each variant also checks, from PostgreSQL's side, that the
// backend leg is what it was set to.
static const int VARIANT_CHECKS = 1 + CASE_F_CHECKS + CASE_G_CHECKS;
static const int PER_MODE_CHECKS = CASE_E_CHECKS + 4 * VARIANT_CHECKS;

// Re-creates the backend rows with use_ssl set as asked. The pool is emptied first: a pooled connection
// keeps the TLS setting it was opened with.
static bool set_backend_tls(PGconn* admin, const std::vector<std::string>& servers, bool tls) {
	return flush_backend_pool(admin, servers) &&
	       exec_ok(admin, std::string("UPDATE pgsql_servers SET use_ssl = ") + (tls ? "1" : "0") +
	                      " WHERE hostgroup_id = " + std::to_string(BACKEND_HG)) &&
	       exec_ok(admin, "LOAD PGSQL SERVERS TO RUNTIME");
}

static void cases_E_F_G_all_modes() {
	PGconn* admin = open_admin();
	if (!admin || !create_commit_fixtures()) {
		ok(0, "case E/F/G: admin connection and fixtures");
		emit_fail_fill(2 * PER_MODE_CHECKS - 1, "case E/F/G aborted on setup");
		if (admin) PQfinish(admin);
		return;
	}
	const bool native_supported = pgsql_native_supported(admin);
	PGresult* r = PQexec(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
	const std::string orig_native = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	const std::vector<std::string> servers = read_servers(admin);
	// Case G's query rule: an error of ProxySQL's, with the backend alive. Case F's: multiplex=0.
	const bool rule_ok = exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id = " + std::to_string(RULE_G_ID)) &&
		exec_ok(admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (" +
			std::to_string(RULE_G_ID) + ", 1, 'txp_g_blocked', 'blocked by a query rule', 1)") &&
		exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id = " + std::to_string(RULE_F_MUX_ID)) &&
		exec_ok(admin, "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, multiplex, apply) VALUES (" +
			std::to_string(RULE_F_MUX_ID) + ", 1, 'txp_f_mux_off', 0, 1)") &&
		exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");

	for (const bool native : { false, true }) {
		const char* mode = native ? "native" : "libpq";
		if (native && !native_supported) {
			skip(PER_MODE_CHECKS, "native backend protocol is unavailable on this tier");
			continue;
		}
		if ((native_supported && !set_admin_bool("use_native_backend_protocol", native)) ||
		    !flush_backend_pool(admin, servers)) {
			emit_fail_fill(PER_MODE_CHECKS, "case E/F/G: cannot switch the backend protocol");
			continue;
		}
		case_E_unanswered_commit(mode);
		for (const bool client_tls : { false, true }) {
			for (const bool backend_tls : { true, false }) {
				const std::string variant = std::string(mode) + (client_tls ? ", client TLS" : ", client plain") +
				                            (backend_tls ? ", backend TLS" : ", backend plain");
				if (!set_backend_tls(admin, servers, backend_tls)) {
					emit_fail_fill(VARIANT_CHECKS, ("case F/G [" + variant + "]: cannot set the backend TLS").c_str());
					continue;
				}
				g_client_tls = client_tls;
				const std::string leg = backend_leg_tls();
				ok(leg == (backend_tls ? "true" : "false"),
				   "case F/G [%s]: PostgreSQL sees the backend leg as ssl=%s (expected %s)", variant.c_str(),
				   leg.empty() ? "(unknown)" : leg.c_str(), backend_tls ? "true" : "false");
				case_F_session_state(variant.c_str(), native);
				if (rule_ok) {
					case_G_local_error_keeps_session_state(variant.c_str(), admin);
				} else {
					emit_fail_fill(CASE_G_CHECKS, "case G: cannot install the query rule");
				}
				g_client_tls = false;
			}
		}
	}

	if (native_supported && !orig_native.empty()) {
		set_admin_bool("use_native_backend_protocol", orig_native == "true");
	}
	flush_backend_pool(admin, servers);
	exec_ok(admin, "DELETE FROM pgsql_query_rules WHERE rule_id IN (" + std::to_string(RULE_G_ID) + ", " +
	               std::to_string(RULE_F_MUX_ID) + ", " + std::to_string(RULE_G_HG_ID) + ")");
	exec_ok(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	drop_commit_fixtures();
	PQfinish(admin);
}

int main(int /*argc*/, char** /*argv*/) {
	// Plan breakdown:
	// case A: 8 assertions (BEGIN, ERR shape, notice shape, no-57P01-in-notice,
	//   PQstatus, PQtransactionStatus, reject-batch, ROLLBACK WORK recovers,
	//   post-recovery SELECT 1, victim gone, counters) -- wait counted = 11
	//   let me recount manually below.
	// case A ok() count = 11
	// case B ok() count = 3
	// case C ok() count = 1
	// case D ok() count = 2
	// case E ok() count = CASE_E_CHECKS per backend protocol (libpq, native)
	// case F and G run in 4 TLS variants per backend protocol (libpq, native), each with
	//   1 check of the backend leg + CASE_F_CHECKS + CASE_G_CHECKS: VARIANT_CHECKS
	// PER_MODE_CHECKS = CASE_E_CHECKS + 4 * VARIANT_CHECKS
	// Total = 17 + 2 * PER_MODE_CHECKS
	plan(17 + 2 * PER_MODE_CHECKS);

	srand((unsigned int)time(nullptr) ^ (unsigned int)getpid());

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	// Scope-guard the admin variable: restored to default=true even if the
	// test aborts early. Without this, case_D leaving admin=false would
	// contaminate subsequent tests on the same ProxySQL instance.
	RestorePreserveClientAdminVar admin_guard;

	if (!set_admin_bool("preserve_client_on_broken_backend_in_tx", true)) {
		diag("Failed to prime admin variable to true; aborting test.");
		return EXIT_FAILURE;
	}

	case_A_rollback_recovery();
	case_B_commit_recovery();
	case_C_autocommit_no_poison();
	case_D_admin_off();
	// case D left the admin variable off; cases E and F need the poison on.
	set_admin_bool("preserve_client_on_broken_backend_in_tx", true);
	cases_E_F_G_all_modes();

	return exit_status();
}
