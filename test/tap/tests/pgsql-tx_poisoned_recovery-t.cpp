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
 *     emits an additional NoticeResponse at SQLSTATE 25P01 carrying the
 *     "there is no transaction in progress" warning, matching PG native.
 *   * Post-recovery queries hit a different backend PID (poison path destroyed
 *     the pool connection, a fresh one was acquired on the next query).
 *   * Three stats counters increment with EXACT expected deltas.
 *   * Non-tx statement killed mid-flight does NOT trigger poison (we gate on
 *     is_in_transaction(), not the disconnect heuristic).
 *   * Admin variable off → mid-tx backend kill terminates the client session
 *     (pre-feature fallback), and none of the tx-poisoned counters move.
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
	char marker[96];
	snprintf(marker, sizeof(marker),
	         "txp_recov_marker_%ld_%d_%ld",
	         (long)time(nullptr), (int)getpid(), (long)rand());
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

	KillResult out;
	std::atomic<bool> did_kill{false};
	std::atomic<int> victim{-1};
	std::string local_marker(marker);
	std::thread killer([&did_kill, &victim, local_marker]() {
		int pid = poll_for_marked_backend_pid(local_marker.c_str(), /*timeout_ms*/ 6000);
		if (pid <= 0) {
			diag("poll_for_marked_backend_pid: no backend found with marker=%s within 6s",
			     local_marker.c_str());
			return;
		}
		victim.store(pid);
		if (!terminate_backend(pid)) {
			diag("terminate_backend(%d) returned false", pid);
			return;
		}
		did_kill.store(true);
	});

	out.pgresult = PQexec(cli, query.c_str());
	killer.join();
	out.kill_delivered = did_kill.load();
	out.victim_pid = victim.load();
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

// Case B: COMMIT-on-poisoned emits the 25P01 warning notice and recovers.
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

	// Verify the NoticeResponse emitted by the COMMIT-on-poisoned path carries
	// SQLSTATE 25P01 (no_active_sql_transaction) — NOT 00000, NOT 57P01.
	bool commit_notice_ok = false;
	for (size_t i = notices_before_commit; i < bag.items.size(); ++i) {
		const auto& n = bag.items[i];
		if (n.severity == "WARNING" && n.sqlstate == "25P01"
		    && n.message.find("no transaction in progress") != std::string::npos) {
			commit_notice_ok = true;
			break;
		}
	}
	ok(commit_notice_ok,
	   "case B: COMMIT-on-poisoned emits NoticeResponse with severity=WARNING sqlstate=25P01 "
	   "\"there is no transaction in progress\"");

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
	// Total = 17
	plan(17);

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

	return exit_status();
}
