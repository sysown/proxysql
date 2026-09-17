/**
 * @file pgsql-native_extq_orphaned_sync-t.cpp
 * @brief A frame refused inside ProxySQL must not leave the backend mid-batch, and must not
 *        commit what that batch already did.
 *
 * In the extended query protocol a client sends several messages and ends them with a Sync.
 * PostgreSQL treats the batch as unfinished until that Sync arrives: it keeps an implicit
 * transaction open, holds the locks the statements took, and sends no ReadyForQuery.
 *
 * ProxySQL queues those messages and works through them one at a time, sending each to the backend
 * and waiting for the reply. Every message except the last goes out Flush-terminated ("more is
 * coming"); only the last carries the Sync.
 *
 * Some of them can fail inside ProxySQL without ever reaching PostgreSQL. Describing a prepared
 * statement ProxySQL has no record of is the clearest case: it answers the client itself and throws
 * the rest of the frame away. When the failing message is the LAST one, the Sync goes with it -- and
 * the messages already sent are still sitting on the backend, unfinished.
 *
 * Every frame here is built so the failing message is the last one:
 *
 *     Parse / Bind / Execute   -> reach the backend, Flush-terminated, and run
 *     Describe(unknown stmt)   -> fails inside ProxySQL; carried the frame's Sync
 *
 * TWO ORACLES, both read from a DIRECT connection to PostgreSQL rather than through ProxySQL --
 * ProxySQL's own view is the thing under test, so asking it would prove nothing.
 *
 * 1. Is a backend left mid-batch?  Keyed on `xact_start IS NOT NULL`, NOT on the state label.
 *    PostgreSQL only moves a session to 'idle' or 'idle in transaction' when it sends
 *    ReadyForQuery, which is exactly what a batch missing its Sync never gets -- so a stranded
 *    session sits at 'active' and a state-based check walks straight past it.
 *
 * 2. Is a WRITE from a refused frame made durable?  Closing a batch COMMITS it; it does not abort
 *    it. Real PostgreSQL would have discarded the work, because there the failing message reaches
 *    the backend and poisons the batch -- here it fails inside ProxySQL and the backend never
 *    learns of any error. So "recovering" such a connection by finishing its batch would make the
 *    row durable after the client was told the batch failed. The row must be gone.
 *
 * Each write scenario carries a nextval() as a tripwire. A sequence is not rolled back, so one that
 * MOVED proves that scenario's Execute really ran on the backend. Without it, "no row" cannot be
 * told apart from "the write never got there", and the assertion would pass while proving nothing.
 * That is not hypothetical: two earlier revisions of this test passed for exactly that reason.
 *
 * The probe table lives in the database the CLIENT connects to, which is named after the user --
 * not in 'postgres'. Put it in the wrong one and the Parse fails with "relation does not exist",
 * the frame dies at the Parse, and the Execute never runs.
 *
 * The write oracles are read WHILE THE CLIENT IS STILL CONNECTED. If the client disconnects first,
 * ProxySQL tears its session down and the backend connection dies with it, which rolls the write
 * back for a reason that has nothing to do with the behaviour under test. A real client stays
 * connected after its batch is refused.
 *
 * ALL FOUR SCENARIOS RUN ON BOTH BACKEND PATHS. Despite this file's name, the defect is not
 * native-only: libpq's pipeline sync finishes an unterminated batch exactly as a raw Sync does.
 * Running both also makes a failure attributable -- if one path fails and the other does not, the
 * frame itself is well-formed and the difference is in the backend leg. The pool is drained between
 * scenarios, because a pooled connection is not converted when the mode flips and both would
 * otherwise measure the same path.
 *
 * ONE MORE SCENARIO, the mirror image of the four above: the last message is answered locally
 * with SUCCESS (a statement Close, 'S') instead of an error. The client is told the frame worked,
 * so the batch must be CONCLUDED by sending its Sync, not discarded. Before the fix this crashed
 * the whole proxy in native mode, which is why the first assertion checks it is still alive.
 *
 * Only LOAD ... TO RUNTIME is used (never SAVE ... TO DISK); the harness reloads config from disk
 * before each test. Any backend session a scenario strands is terminated before the next one runs,
 * because its locks would otherwise change what the next scenario measures.
 */
#include <chrono>
#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <unistd.h>
#include "libpq-fe.h"
#include "pg_lite_client.h"  // raw stepwise frontend  (MUST precede utils.h: mysql.h clash)
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int HG = 0;

static PGConnPtr openConn(const char* host, int port, const char* user, const char* pass, const char* db) {
	std::stringstream ss;
	ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static PGConnPtr adminConn() {
	return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, nullptr);
}
static bool exec(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const bool okk = (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
	if (!okk) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return okk;
}
static std::string execScalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

// Backend connections are pooled, and a pooled one is NOT converted between the two paths when the
// mode changes. Without this the second scenario would quietly reuse the first one's connection and
// both would measure the same path. Taking the servers down and back drops what is pooled.
static void resetPool(PGconn* admin) {
	const std::string hg = std::to_string(HG);
	if (!exec(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not take hostgroup %s down", hg.c_str());
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (std::chrono::steady_clock::now() < deadline) {
		const std::string n = execScalar(admin,
			"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup=" + hg);
		if (!n.empty() && atoi(n.c_str()) == 0) break;
		usleep(100000);
	}
	if (!exec(admin, "UPDATE pgsql_servers SET status='ONLINE' WHERE hostgroup_id=" + hg)
	    || !exec(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
		BAIL_OUT("could not bring hostgroup %s back", hg.c_str());
	usleep(200000);
}

static void setNativeMode(PGconn* admin, bool on) {
	const std::string want = on ? "true" : "false";
	if (!exec(admin, "SET pgsql-use_native_backend_protocol='" + want + "'")
	    || !exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME"))
		BAIL_OUT("could not set pgsql-use_native_backend_protocol");
	// Read it back off RUNTIME rather than trusting the SET. A flip that silently does not take is
	// the one failure this whole file cannot survive: every "native" scenario would quietly run on
	// libpq, agree with its libpq twin, and report both paths green while testing one.
	const std::string got = execScalar(admin,
		"SELECT variable_value FROM runtime_global_variables "
		"WHERE variable_name='pgsql-use_native_backend_protocol'");
	if (got != want)
		BAIL_OUT("pgsql-use_native_backend_protocol did not take: wanted '%s', runtime says '%s'",
		         want.c_str(), got.c_str());
	resetPool(admin);
}

// The backend session this frame stranded, if there is one. Polled until it is GONE, not until it
// appears: discarding a connection closes its socket, and PostgreSQL needs a few milliseconds to
// notice, roll back and leave pg_stat_activity, so a session read one round trip after the client's
// error is still there even when ProxySQL did exactly the right thing. Only one that outlives the
// deadline is stranded; a real one sits there until the pool reuses or drops the connection.
static std::string strandedBackendPid(PGconn* be, const std::string& marker) {
	// Keyed on xact_start, not on the state label. PostgreSQL only moves a session to 'idle' or
	// 'idle in transaction' when it sends ReadyForQuery -- which is exactly what a batch missing its
	// Sync never gets -- so a stranded session sits at 'active' and a state-based check walks right
	// past it. An open transaction is what actually holds the locks, so ask about that instead.
	const std::string q =
		"SELECT pid FROM pg_stat_activity WHERE xact_start IS NOT NULL AND query LIKE '%"
		+ marker + "%' AND query NOT LIKE '%pg_stat_activity%' LIMIT 1";
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
	for (;;) {
		const std::string pid = execScalar(be, q);
		if (pid.empty()) return "";
		if (std::chrono::steady_clock::now() >= deadline) return pid;
		usleep(100000);
	}
}

// Whether the backend ever saw this frame at all, and in what state it was left. Without this the
// test cannot tell "no bug" from "the frame never reached the backend, so there was nothing to
// strand" -- both show up as no stranded session, and only one of them means anything.
static std::string backendSightings(PGconn* be, const std::string& marker) {
	PGresult* r = PQexec(be, ("SELECT a.pid, a.state, (a.xact_start IS NOT NULL) AS in_txn, "
		"(SELECT count(*) FROM pg_locks l WHERE l.pid = a.pid AND l.locktype = 'relation') AS relocks "
		"FROM pg_stat_activity a WHERE a.query LIKE '%"
		+ marker + "%' AND a.query NOT LIKE '%pg_stat_activity%'").c_str());
	std::string out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK) {
		for (int i = 0; i < PQntuples(r); i++) {
			if (!out.empty()) out += ", ";
			out += std::string(PQgetvalue(r, i, 0)) + " state=" + PQgetvalue(r, i, 1)
				+ " in_txn=" + PQgetvalue(r, i, 2) + " relation_locks=" + PQgetvalue(r, i, 3);
		}
	}
	PQclear(r);
	return out.empty() ? "none" : out;
}

struct Probe {
	bool client_rejected = false;   // ProxySQL answered the bad Describe itself
	std::string stranded_pid;       // backend session left mid-batch; empty if none
	std::string sightings;          // any backend session that ran the marker, with its state
	std::string detail = "not run";
};

// One frame whose LAST message fails inside ProxySQL. Reports what the client saw and whether the
// backend was left waiting, separately: they are different defects and one boolean would hide that.
static Probe runOrphanedSyncFrame(PGconn* be, const std::string& marker) {
	Probe p;
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

		// Not the last message, so each of these goes out Flush-terminated: the backend answers it
		// and keeps the batch open.
		// nextval() makes this frame's Execute observable the same way the write frame's is: the
		// sequence moves only if the Execute really ran, which is what tells us whether the two
		// frames diverge because of what they do or because of how far they get.
		c.prepareStatement("orphsync_stmt",
			"SELECT '" + marker + "' || nextval('orphsync_seq')::text", false);
		c.bindStatement("orphsync_stmt", "", {}, {}, false);
		c.executePortal("", 0, false);
		// The last message, so this is the one carrying the frame's Sync. ProxySQL has no record of
		// this statement name, so it answers the client and drops the frame -- Sync included.
		c.describeStatement("orphsync_missing_stmt", false);
		c.sendSync();

		// Read until ProxySQL's error, or until it says it is ready again.
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char type = 0;
			std::vector<uint8_t> buffer;
			c.readMessage(type, buffer);
			if (type == PgConnection::ERROR_RESPONSE) {
				p.client_rejected = true;
				continue;
			}
			if (type == PgConnection::READY_FOR_QUERY) break;
		}
		p.stranded_pid = strandedBackendPid(be, marker);
		p.sightings = backendSightings(be, marker);
		p.detail = std::string("client_rejected=") + (p.client_rejected ? "yes" : "no")
			+ ", stranded backend pid=" + (p.stranded_pid.empty() ? "none" : p.stranded_pid)
			+ ", backend sessions that ran the marker (pid=state): " + p.sightings;
	} catch (const PgException& e) {
		// Reported rather than swallowed: the assertions run either way, so a throw shows up as a
		// failure with its reason attached instead of a short plan that hides the whole report.
		p.stranded_pid = strandedBackendPid(be, marker);
		p.sightings = backendSightings(be, marker);
		p.detail = std::string("frame threw: ") + e.what()
			+ " (stranded backend pid=" + (p.stranded_pid.empty() ? "none" : p.stranded_pid)
			+ ", backend sessions that ran the marker: " + p.sightings + ")";
	}
	return p;
}

// Does an abandoned frame leave a WRITE behind? The recovery sends a Sync, and in the extended
// protocol a Sync does not abort the implicit transaction -- it COMMITS it. So an Execute that
// already inserted a row could end up durable even though the client was told its batch failed.
// Real PostgreSQL would have rolled it back: there the failing message reaches the backend and
// poisons the batch, while here it fails inside ProxySQL and the backend never learns of an error.
//
// The probe lives in the database the CLIENT connects to, which is named after the user -- not in
// 'postgres'. Put it in the wrong one and the Parse fails with "relation does not exist", the frame
// dies at the Parse, and the Execute never runs, which proves nothing at all.
static bool insertVisible(PGconn* be_db, const std::string& marker) {
	return execScalar(be_db, "SELECT count(*) FROM orphsync_t WHERE v LIKE '" + marker + "%'") == "1";
}

// A sequence is not rolled back, so one that MOVED across a scenario proves that scenario's Execute
// really ran on the backend. Without it, "no row" cannot be told apart from "the write never got
// there". Read as a value, not is_called: that is one-shot and cannot tell two scenarios apart.
static std::string seqValue(PGconn* be_db, const char* seq = "orphsync_seq") {
	return execScalar(be_db, std::string("SELECT last_value::text FROM ") + seq);
}

// How many times the commit trigger has killed a backend. Counted off is_called as well as
// last_value, because a sequence's last_value does not move on the FIRST nextval -- reading it
// alone misses the first firing entirely.
static long killCount(PGconn* be_db) {
	const std::string n = execScalar(be_db,
		"SELECT CASE WHEN is_called THEN last_value ELSE 0 END FROM orphsync_kill_seq");
	return n.empty() ? -1 : atol(n.c_str());
}

// The client's ReadyForQuery arrives before ProxySQL has necessarily finished with the backend, so
// the resync -- and the commit that fires the trigger -- lands after the frame, not during it.
static bool killedWithin(PGconn* be_db, long before, int seconds) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	for (;;) {
		if (killCount(be_db) > before) return true;
		if (std::chrono::steady_clock::now() >= deadline) return false;
		usleep(100000);
	}
}

// Same frame shape as above, but the Execute writes a row instead of selecting a literal.
// `be_db` is read WHILE THE CLIENT IS STILL CONNECTED. That matters: if the client disconnects
// first, ProxySQL tears its session down and the backend connection dies with it, which rolls the
// write back for a reason that has nothing to do with the recovery being tested. A real client
// stays connected after its batch is refused, so that is what this has to model.
static bool runAbandonedWriteFrame(const std::string& marker, std::string& detail,
                                   PGconn* be_db, std::string* seq_live, bool* visible_live) {
	bool rejected = false;
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		c.prepareStatement("orphsync_w",
			"INSERT INTO orphsync_t (v) VALUES ('" + marker + "' || nextval('orphsync_seq'))", false);
		c.bindStatement("orphsync_w", "", {}, {}, false);
		c.executePortal("", 0, false);
		c.describeStatement("orphsync_missing_stmt", false);
		c.sendSync();
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char type = 0;
			std::vector<uint8_t> buffer;
			c.readMessage(type, buffer);
			if (type == PgConnection::ERROR_RESPONSE) { rejected = true; continue; }
			if (type == PgConnection::READY_FOR_QUERY) break;
		}
		// Still inside the try, so `c` is still open and its session still alive.
		*seq_live = seqValue(be_db);
		*visible_live = insertVisible(be_db, marker);
	} catch (const PgException& e) {
		detail = std::string("write frame threw: ") + e.what();
		return rejected;
	}
	detail = std::string("client_rejected=") + (rejected ? "yes" : "no");
	return rejected;
}

// Terminate a session this scenario stranded, as soon as it has been measured. A stranded session
// keeps its locks on the probe table and sequence, so leaving it alive until teardown lets one
// scenario's wreckage change what the next one sees -- which made results swing between runs.
static void clearStranded(PGconn* be, const std::string& pid) {
	if (pid.empty()) return;
	diag("terminating stranded backend pid %s before the next scenario", pid.c_str());
	exec(be, "SELECT pg_terminate_backend(" + pid + ")");
	usleep(300000);
}

// One refused frame whose Execute writes a row, on whichever backend path is selected. Both paths
// need this: the fix is not native-only, because libpq's pipeline sync finishes an unterminated
// batch exactly as a raw Sync does, and finishing it means committing it.
struct WriteProbe {
	bool rejected = false;
	bool reached = false;        // this scenario's Execute ran on the backend
	bool visible_live = false;   // row visible while the client is still connected
	bool visible_after = false;  // ... and after it disconnects
	std::string detail = "not run";
};

static WriteProbe runWriteScenario(PGconn* admin, PGconn* be_db, const std::string& marker,
                                   bool native, const char* label) {
	WriteProbe w;
	setNativeMode(admin, native);
	const std::string seq_before = seqValue(be_db);
	std::string seq_live = seq_before;
	w.rejected = runAbandonedWriteFrame(marker, w.detail, be_db, &seq_live, &w.visible_live);
	w.reached = (seq_live != seq_before);
	w.visible_after = insertVisible(be_db, marker);
	diag("%s write frame: %s, sequence %s -> %s (moved = its Execute ran)",
	     label, w.detail.c_str(), seq_before.c_str(), seq_live.c_str());
	diag("%s write frame: row visible WHILE the client is still connected=%s; after it disconnects=%s",
	     label, w.visible_live ? "YES" : "no", w.visible_after ? "YES" : "no");
	diag("%s write frame: backend sessions for the marker: %s",
	     label, backendSightings(be_db, marker).c_str());
	return w;
}

static void reportWrite(const char* label, const WriteProbe& w) {
	ok(w.rejected, "%s: the write frame is rejected at the client [%s]", label, w.detail.c_str());
	ok(w.reached,
	   "%s: the abandoned frame's Execute DID run on the backend -- without this the row being "
	   "absent below would prove nothing [sequence moved=%s]", label, w.reached ? "YES" : "no");
	ok(!w.visible_live,
	   "%s: a row written by a refused frame must NOT be committed -- the client was told the batch "
	   "failed, so recovering the connection must not make its write durable [row visible=%s]",
	   label, w.visible_live ? "YES" : "no");
}

// ---------------------------------------------------------------------------------------------
// Guards against the change being too broad, and against it destroying state the client still owns.
// ---------------------------------------------------------------------------------------------

struct HealthyProbe {
	bool completed = false;      // ran to ReadyForQuery with no ErrorResponse
	bool conn_survived = false;  // a backend session for this marker still exists afterwards
	std::string detail = "not run";
};

// A frame that is NOT refused: Parse / Bind / Execute / Sync, nothing wrong with it. Its connection
// must survive. Without this scenario the change could be discarding a connection after EVERY
// extended query and every other assertion in this file would still pass.
//
// `second_marker`, when given, runs a REFUSED frame first on the same client session. That is the
// stale-mark guard: the "this frame was refused" mark is cleared when the next frame starts, and if
// it were not, every frame after a refused one would discard its connection too.
static HealthyProbe runHealthyFrame(PGconn* be_db, const std::string& marker,
                                    bool refuse_one_first) {
	HealthyProbe h;
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

		if (refuse_one_first) {
			c.prepareStatement("orphsync_pre", "SELECT 1", false);
			c.describeStatement("orphsync_missing_stmt", false);
			c.sendSync();
			const auto d0 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
			while (std::chrono::steady_clock::now() < d0) {
				char t = 0; std::vector<uint8_t> b;
				c.readMessage(t, b);
				if (t == PgConnection::READY_FOR_QUERY) break;
			}
		}

		c.prepareStatement("orphsync_ok",
			"INSERT INTO orphsync_t (v) VALUES ('" + marker + "' || nextval('orphsync_seq'))", false);
		c.bindStatement("orphsync_ok", "", {}, {}, false);
		c.executePortal("", 0, false);
		c.sendSync();

		bool errored = false;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char t = 0; std::vector<uint8_t> b;
			c.readMessage(t, b);
			if (t == PgConnection::ERROR_RESPONSE) { errored = true; continue; }
			if (t == PgConnection::READY_FOR_QUERY) break;
		}
		h.completed = !errored;
		// Read while the client is still connected: a backend session still running this marker
		// means the connection was not thrown away.
		h.conn_survived = (backendSightings(be_db, marker) != "none");
		h.detail = std::string("completed=") + (h.completed ? "yes" : "no")
			+ ", backend sessions: " + backendSightings(be_db, marker);
	} catch (const PgException& e) {
		h.detail = std::string("frame threw: ") + e.what();
	}
	return h;
}

// A frame refused INSIDE a client's explicit transaction. Discarding the backend connection
// destroys that transaction, and the client is never told -- it still believes it is inside one.
// The sharp question is what its next statement does: if the transaction is silently gone, an
// INSERT after it autocommits and SURVIVES the client's own ROLLBACK. That is data the client
// explicitly rolled back, left durable.
static bool explicitTxnNotSilentlyLost(PGconn* be_db, const std::string& marker, std::string& detail) {
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		c.execute("BEGIN");
		c.waitForReady();

		// Refused frame, inside the transaction.
		c.prepareStatement("orphsync_tx", "SELECT 1", false);
		c.describeStatement("orphsync_missing_stmt", false);
		c.sendSync();
		const auto d0 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < d0) {
			char t = 0; std::vector<uint8_t> b;
			c.readMessage(t, b);
			if (t == PgConnection::READY_FOR_QUERY) break;
		}

		// Now write something and roll it back. Either the write errors (transaction known to be
		// broken) or it is rolled back -- both are fine. What is NOT fine is it quietly surviving.
		std::string post = "not attempted";
		try {
			c.execute("INSERT INTO orphsync_t (v) VALUES ('" + marker + "')");
			c.waitForReady();
			post = "insert accepted";
		} catch (const PgException& ie) {
			post = std::string("insert refused: ") + ie.what();
		}
		try {
			c.execute("ROLLBACK");
			c.waitForReady();
			post += "; rollback accepted";
		} catch (const PgException& re) {
			post += std::string("; rollback refused: ") + re.what();
		}
		const bool durable = (execScalar(be_db,
			"SELECT count(*) FROM orphsync_t WHERE v = '" + marker + "'") == "1");
		detail = post + "; row durable after ROLLBACK=" + (durable ? "YES" : "no");
		return !durable;
	} catch (const PgException& e) {
		detail = std::string("transaction scenario threw: ") + e.what();
		return false;
	}
}

// Put a connection INTO the pool, so the scenario after this runs on a reused one rather than a
// fresh one. Every other scenario here drains the pool to stop them contaminating each other, with
// the side effect that none of them exercises the ordinary production case: a refused frame on a
// connection that has already served somebody.
static void warmPool(const std::string& marker) {
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		c.execute("SELECT '" + marker + "'::text");
		c.waitForReady();
	} catch (const PgException&) {
		// Warming is best-effort; the scenario still runs, just possibly on a fresh connection.
	}
}

// The harm this bug actually does. A connection left mid-batch goes back into the pool and the NEXT
// client picks it up, inheriting an open transaction it never started. Everything else in this file
// checks the connection was not LEFT stranded; this checks nobody else can catch it.
//
// The oracle is the bystander's own write. On a clean connection it autocommits and is visible from
// outside immediately. Inherited inside somebody else's still-open transaction it would not be --
// it would sit invisible until that transaction ended. Read while the bystander is still connected,
// so its own disconnect cannot commit or roll anything back and mask the answer.
static bool bystanderUnaffected(PGconn* be_db, const std::string& marker, std::string& detail) {
	try {
		PgConnection b(5000);
		b.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		b.execute("INSERT INTO orphsync_t (v) VALUES ('" + marker + "')");
		b.waitForReady();
		const bool visible =
			(execScalar(be_db, "SELECT count(*) FROM orphsync_t WHERE v = '" + marker + "'") == "1");
		detail = std::string("bystander write visible immediately=") + (visible ? "yes" : "NO");
		return visible;
	} catch (const PgException& e) {
		detail = std::string("bystander threw: ") + e.what();
		return false;
	}
}

// A frame whose Execute fails AT THE BACKEND. The batch is poisoned, so PostgreSQL discards it when
// the batch is finished -- which means the connection is safe to finish and keep. This is the half of
// the rule that says a Sync is only dangerous when ProxySQL swallowed the error, and without it
// nothing here could tell a correct implementation from one that discards on every failed query.
// The SQLSTATE out of an ErrorResponse payload: a run of (field code, NUL-terminated value) pairs
// ended by a zero byte, where field 'C' is the code. Returns "" when it is not there. Used to tell
// an error PostgreSQL raised from one ProxySQL raised on its own behalf, which look identical to a
// client but mean opposite things for everything below.
static std::string errorSqlstate(const std::vector<uint8_t>& payload) {
	size_t i = 0;
	while (i < payload.size() && payload[i] != 0) {
		const char code = (char)payload[i++];
		const size_t start = i;
		while (i < payload.size() && payload[i] != 0) i++;
		if (code == 'C') return std::string((const char*)payload.data() + start, i - start);
		if (i < payload.size()) i++;   // step over the value's NUL
	}
	return "";
}

// Run one simple query on the raw connection and say whether it succeeded, with the SQLSTATE when it
// did not. PgConnection::execute() throws on failure, and here a failure is an expected outcome that
// has to be inspected rather than escaped from.
static bool rawSimple(PgConnection& c, const std::string& sql, std::string& sqlstate) {
	sqlstate.clear();
	c.sendQuery(sql);
	bool err = false;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline) {
		char t = 0; std::vector<uint8_t> b;
		c.readMessage(t, b);
		if (t == PgConnection::ERROR_RESPONSE) { err = true; sqlstate = errorSqlstate(b); continue; }
		if (t == PgConnection::READY_FOR_QUERY) return !err;
	}
	return false;
}

struct FlushResyncProbe {
	bool errored = false;            // the client saw an ErrorResponse
	std::string sqlstate;            // and this is whose error it was
	bool got_ready = false;          // a ReadyForQuery arrived -- see the scenario comment
	char rfq_status = '?';           // its transaction-status byte
	bool followup_ok = false;        // a further query on the SAME connection succeeded
	std::string followup_sqlstate;   // or why it did not
	bool rollback_ok = false;        // explicit-transaction runs only
	bool after_rollback_ok = false;
	std::string detail = "not run";
};

// A frame whose PARSE fails on the backend, with Bind/Execute/Sync still queued behind it.
//
// That shape is the whole point. ProxySQL puts the Sync on the frame's LAST message only, so a Parse
// with messages after it goes out Flush-terminated -- and PostgreSQL, after an error on a
// Flush-terminated message, discards everything until it sees a Sync and sends NO ReadyForQuery of
// its own. Somebody has to produce that Sync or the connection is stuck waiting on a message that
// will never come.
//
// Contrast with runBackendErrorFrame() above, which fails on 1/0: that is only discovered while
// EXECUTING, and the Execute is the last message, so it carries the client's Sync and PostgreSQL
// answers by itself. Nothing is recovered there, which is why it cannot stand in for this.
static FlushResyncProbe runFlushTerminatedParseError(PGconn* be_db, const std::string& marker,
                                                bool explicit_txn) {
	FlushResyncProbe p;
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

		std::string scratch;
		if (explicit_txn && !rawSimple(c, "BEGIN", scratch)) {
			p.detail = "BEGIN failed before the frame could run";
			return p;
		}

		// The table does not exist, so this fails while the backend is still analysing the Parse --
		// before any Bind or Execute. The marker rides in the query text so the backend session can
		// be found afterwards.
		const std::string sql = "SELECT '" + marker + "'::text FROM " + marker + "_missing";
		c.prepareStatement("orphsync_resync", sql, false);
		c.bindStatement("orphsync_resync", "", {}, {}, false);
		c.executePortal("", 0, false);
		c.sendSync();

		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char t = 0; std::vector<uint8_t> b;
			c.readMessage(t, b);
			if (t == PgConnection::ERROR_RESPONSE) {
				p.errored = true;
				if (p.sqlstate.empty()) p.sqlstate = errorSqlstate(b);
				continue;
			}
			if (t == PgConnection::READY_FOR_QUERY) {
				p.got_ready = true;
				if (!b.empty()) p.rfq_status = (char)b[0];
				break;
			}
		}

		if (p.got_ready) {
			p.followup_ok = rawSimple(c, "SELECT 42", p.followup_sqlstate);
			if (explicit_txn) {
				p.rollback_ok = rawSimple(c, "ROLLBACK", scratch);
				p.after_rollback_ok = rawSimple(c, "SELECT 42", scratch);
			}
		}

		p.detail = std::string("errored=") + (p.errored ? "yes" : "no")
			+ " sqlstate=" + (p.sqlstate.empty() ? "-" : p.sqlstate)
			+ " ready=" + (p.got_ready ? "yes" : "NO")
			+ " rfq_status=" + std::string(1, p.rfq_status)
			+ " followup=" + (p.followup_ok ? "ok"
				: ("failed/" + (p.followup_sqlstate.empty() ? std::string("-") : p.followup_sqlstate)))
			+ (explicit_txn ? (std::string(" rollback=") + (p.rollback_ok ? "ok" : "failed")
				+ " after_rollback=" + (p.after_rollback_ok ? "ok" : "failed")) : std::string())
			+ ", backend sessions: " + backendSightings(be_db, marker);
	} catch (const PgException& e) {
		p.detail = std::string("resync frame threw: ") + e.what();
	}
	return p;
}

static HealthyProbe runBackendErrorFrame(PGconn* be_db, const std::string& marker) {
	HealthyProbe h;
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		// The division is what fails, and it fails on the server. The marker rides along in the query
		// text so the backend session can be found afterwards.
		c.prepareStatement("orphsync_err",
			"SELECT '" + marker + "'::text, 1/0", false);
		c.bindStatement("orphsync_err", "", {}, {}, false);
		c.executePortal("", 0, false);
		c.sendSync();

		bool errored = false;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char t = 0; std::vector<uint8_t> b;
			c.readMessage(t, b);
			if (t == PgConnection::ERROR_RESPONSE) { errored = true; continue; }
			if (t == PgConnection::READY_FOR_QUERY) break;
		}
		h.completed = errored;   // here an error is the EXPECTED outcome
		h.conn_survived = (backendSightings(be_db, marker) != "none");
		h.detail = std::string("backend errored=") + (errored ? "yes" : "no")
			+ ", backend sessions: " + backendSightings(be_db, marker);
	} catch (const PgException& e) {
		h.detail = std::string("frame threw: ") + e.what();
	}
	return h;
}

// ProxySQL's count of backend connections that are up. A gauge, so once every connection a scenario
// made has gone, it has to read what it read before. Same source as pgsql-backend_death_query_retry-t.
static long connectedGauge(PGconn* admin) {
	const std::string n = execScalar(admin,
		"SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='Server_Connections_connected'");
	return n.empty() ? -1 : atol(n.c_str());
}

// What the hostgroup is holding: in use plus idle. Server_Connections_connected does NOT answer
// this -- a connection torn down by a failed resync has already been subtracted from that counter
// while the object itself is still sitting in ConnFree, waiting to be handed to the next client.
static long pooledConns(PGconn* admin) {
	const std::string n = execScalar(admin,
		"SELECT COALESCE(SUM(ConnUsed+ConnFree),0) FROM stats_pgsql_connection_pool WHERE hostgroup="
		+ std::to_string(HG));
	return n.empty() ? -1 : atol(n.c_str());
}

static long pooledConnsWithin(PGconn* admin, long want, int seconds) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	long last = -1;
	for (;;) {
		last = pooledConns(admin);
		if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
		usleep(100000);
	}
}

// A destroyed connection subtracts itself a moment after it leaves the pool, so poll rather than
// read once -- a single read races the reaper and fails for the wrong reason.
static long connectedGaugeWithin(PGconn* admin, long want, int seconds) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	long last = -1;
	for (;;) {
		last = connectedGauge(admin);
		if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
		usleep(100000);
	}
}

// A frame abandoned by a DIFFERENT route than the rest of this file. Every other scenario fails on
// a Describe of an unknown statement; these fail on a statement that cannot run inside an
// extended-query frame at all. They reach the discard through separate code, and each one runs a
// different amount of session teardown afterwards -- the COPY route in particular calls finishQuery
// straight after the frame is thrown away, on a connection that is no longer there. If the discard
// only works for the Describe route, or leaves anything behind it dereferencing a dead connection,
// these are what say so.
static WriteProbe runRefusedStatementScenario(PGconn* admin, PGconn* be_db, const std::string& marker,
                                              bool native, const char* label,
                                              const char* bad_sql, const char* route) {
	WriteProbe w;
	setNativeMode(admin, native);
	const std::string seq_before = seqValue(be_db);
	std::string seq_live = seq_before;
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		// Real work first, so the backend is genuinely mid-batch when the frame is thrown away.
		c.prepareStatement("orphsync_d",
			"INSERT INTO orphsync_t (v) VALUES ('" + marker + "' || nextval('orphsync_seq'))", false);
		c.bindStatement("orphsync_d", "", {}, {}, false);
		c.executePortal("", 0, false);
		// The message that fails, and it carries the frame's Sync with it.
		c.prepareStatement("orphsync_d2", bad_sql, false);
		c.bindStatement("orphsync_d2", "", {}, {}, false);
		c.executePortal("", 0, false);
		c.sendSync();

		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char type = 0; std::vector<uint8_t> buffer;
			c.readMessage(type, buffer);
			if (type == PgConnection::ERROR_RESPONSE) { w.rejected = true; continue; }
			if (type == PgConnection::READY_FOR_QUERY) break;
		}
		// Read while the client is still connected, for the reason given on runAbandonedWriteFrame.
		seq_live = seqValue(be_db);
		w.visible_live = insertVisible(be_db, marker);
		w.detail = std::string("client_rejected=") + (w.rejected ? "yes" : "no");
	} catch (const PgException& e) {
		w.detail = std::string(route) + "-route frame threw: " + e.what();
	}
	w.reached = (seq_live != seq_before);
	w.visible_after = insertVisible(be_db, marker);
	diag("%s %s-route frame: %s, sequence %s -> %s (moved = its Execute ran)",
	     label, route, w.detail.c_str(), seq_before.c_str(), seq_live.c_str());
	diag("%s %s-route frame: backend sessions for the marker: %s",
	     label, route, backendSightings(be_db, marker).c_str());
	return w;
}

// Refused frames destroy their backend connection. Destroying on a path that runs per query is how
// pool slots leak, and nothing else here would notice: every other assertion is about one frame, and
// a leak only shows up as a number that never comes back down. Several frames in a row, so a leak of
// one per refusal is unmistakable rather than a rounding difference.
static const int DISCARD_LEAK_ROUNDS = 3;

static bool runLeakRounds(const std::string& base, PGconn* be_db, bool* reached_backend) {
	bool all_rejected = true;
	// The sequence is the tripwire. A gauge that starts at zero and ends at zero also describes
	// rounds that never opened a backend connection at all, and that reading would pass the leak
	// assertion while measuring nothing. A sequence survives rollback, so one that moved on every
	// round proves every round really executed on a backend.
	const std::string seq_before = seqValue(be_db);
	for (int i = 0; i < DISCARD_LEAK_ROUNDS; i++) {
		std::string detail;
		std::string seq_live;
		bool visible_live = false;
		if (!runAbandonedWriteFrame(base + "_leak" + std::to_string(i), detail, be_db,
		                            &seq_live, &visible_live)) {
			all_rejected = false;
			diag("leak round %d was not rejected: %s", i, detail.c_str());
		}
	}
	const std::string seq_after = seqValue(be_db);
	*reached_backend = (!seq_before.empty() && seq_after != seq_before);
	diag("leak rounds: sequence %s -> %s (moved = every round reached a backend)",
	     seq_before.c_str(), seq_after.c_str());
	return all_rejected;
}

// Mirror image of the scenarios above: the frame's LAST message (a statement Close) is answered
// locally with SUCCESS, not an error. pgjdbc's own frame shape (Parse/Bind/Execute/Close/Sync)
// triggers this: Execute isn't last, so it goes out Flush-terminated with no ReadyForQuery, and
// the trailing Close is answered locally without reaching the backend -- leaving the batch open
// when the frame empties. The client was already told the frame SUCCEEDED, so the fix must
// CONCLUDE the batch by sending the Sync, not discard the connection like the scenarios above.
struct ResyncProbe {
	bool proxy_alive = false;   // a second, unrelated admin query still gets an answer
	bool completed = false;     // this session's own frame ran to ReadyForQuery with no error
	bool stranded = false;      // backend left mid-batch afterwards
	bool seq_moved = false;     // the Execute really ran (tripwire)
	bool row_visible = false;   // the write DID commit -- required, not forbidden, here
	std::string detail = "not run";
};

static ResyncProbe runLocallyClosedSyncFrame(PGconn* admin, PGconn* be_db, const std::string& marker) {
	ResyncProbe r;
	const std::string seq_before = seqValue(be_db);
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

		// Not the last message: goes out Flush-terminated, backend answers it, batch stays open.
		c.prepareStatement("orphsync_rs",
			"INSERT INTO orphsync_t (v) VALUES ('" + marker + "' || nextval('orphsync_seq'))", false);
		c.bindStatement("orphsync_rs", "", {}, {}, false);
		c.executePortal("", 0, false);
		// The last message: a statement Close is answered LOCALLY, with success, and never
		// reaches the backend. It carries the frame's Sync.
		c.closeStatement("orphsync_rs", false);
		c.sendSync();

		bool errored = false;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char type = 0;
			std::vector<uint8_t> buffer;
			c.readMessage(type, buffer);
			if (type == PgConnection::ERROR_RESPONSE) { errored = true; continue; }
			if (type == PgConnection::READY_FOR_QUERY) break;
		}
		r.completed = !errored;
		// Polled, not a single check: the client's ReadyForQuery is sent as part of the local
		// Close answer before the backend resync round-trip even starts, so the write's commit
		// lands a little later (still inside the try, so `c`'s session is still alive).
		const auto row_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < row_deadline) {
			if (insertVisible(be_db, marker)) { r.row_visible = true; break; }
			usleep(50000);
		}
	} catch (const PgException& e) {
		r.detail = std::string("frame threw: ") + e.what();
	}
	const std::string seq_after = seqValue(be_db);
	r.seq_moved = (!seq_before.empty() && seq_after != seq_before);
	r.stranded = !strandedBackendPid(be_db, marker).empty();
	// A second, unrelated admin query: before the fix this scenario aborts the whole process,
	// so nothing here would even run.
	r.proxy_alive = exec(admin, "SELECT 1");
	if (r.detail == "not run") {
		r.detail = std::string("completed=") + (r.completed ? "yes" : "no")
			+ ", row visible=" + (r.row_visible ? "yes" : "no")
			+ ", sequence moved=" + (r.seq_moved ? "yes" : "no")
			+ ", stranded=" + (r.stranded ? "yes" : "no");
	}
	return r;
}

// The scenario above ends with a resync that SUCCEEDS. This one makes the resync itself fail:
// the backend is killed before the trailing Close (still answered locally either way) triggers
// it, so the Sync the resync tries to send goes to a connection that is already gone. Before
// this session's fix, `async_perform_resync()`'s ASYNC_RESYNC_END decided success/failure from
// `resync_failed` alone -- a flag set only on two libpq send paths (PQsendPipelineSync/PQflush
// failures) that predate native entirely. Neither native's own failures nor a libpq backend
// dying while the resync waits for its reply ever set that flag, so the resync reported success
// or a rebuilt native connection got pooled anyway, and `push_MyConn_to_pool()` has no liveness
// check of its own -- a dead connection would sit in ConnectionsFree until some later client
// drew it and failed for a completely unrelated reason.
//
// The backend cannot be killed from outside at the right moment. ProxySQL forwards nothing until
// the frame's Sync arrives, so until then there is no backend running this frame to kill; once it
// does arrive, the whole frame -- Execute, local Close and the resync's own Sync -- goes through in
// one pass, and the gap to aim at is microseconds wide. So the backend kills itself instead: the
// row this Execute writes carries a DEFERRABLE INITIALLY DEFERRED constraint trigger, which fires
// when the implicit transaction commits, and that commit is exactly what ProxySQL's resync Sync
// asks for. The backend accepts the Sync and dies without replying -- the DRAIN side of
// `resync_failed || is_error_present()`, deterministic and with no mock backend.
struct ResyncFailureProbe {
	bool insert_ran = false;    // the Execute really reached the backend (tripwire)
	bool kill_fired = false;    // the commit trigger ran, so the resync's Sync DID reach the
	                             // backend and the backend DID die on it -- without this the
	                             // whole scenario passes on an ordinary successful frame
	bool client_ok = false;     // the client's own frame still completes cleanly -- Close is
	                             // answered locally either way, so the client never sees the
	                             // backend's death
	long gauge_baseline = -1;
	long gauge_after = -1;      // the connected-backend count returns to baseline: nothing was
	                             // left counted as connected
	long pool_baseline = -1;
	long pool_live = -1;        // what the hostgroup holds WHILE THE CLIENT IS STILL CONNECTED: a
	                             // resync that fails must DESTROY the connection, not leave a dead
	                             // one in ConnFree for the next client to draw. Read before the
	                             // client goes away, because closing the session destroys the
	                             // connection on its own and hides the difference
	bool bystander_ok = false;  // a fresh client on the same hostgroup gets a healthy connection
	bool row_visible = false;    // reported, not asserted: the backend died mid-commit, so its
	                             // write is gone even though the client was told it succeeded
	std::string detail = "not run";
};

static ResyncFailureProbe runResyncFailure(PGconn* admin, PGconn* be_db, const std::string& marker) {
	ResyncFailureProbe r;
	r.gauge_baseline = connectedGauge(admin);
	r.pool_baseline = pooledConns(admin);
	const std::string seq_before = seqValue(be_db);
	const long kill_before = killCount(be_db);
	try {
		PgConnection c(5000);
		c.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

		// The marker makes this row the one the commit trigger fires on.
		c.prepareStatement("resyncfail_rs",
			"INSERT INTO orphsync_t (v) VALUES ('" + marker + "' || nextval('orphsync_seq'))", false);
		c.bindStatement("resyncfail_rs", "", {}, {}, false);
		c.executePortal("", 0, false);

		// The last message: a statement Close, answered LOCALLY regardless of backend state. The
		// batch is left open, so ProxySQL concludes it with a Sync of its own -- which commits,
		// which fires the trigger, which kills the backend while the resync waits for the reply.
		c.closeStatement("resyncfail_rs", false);
		c.sendSync();

		bool errored = false;
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (std::chrono::steady_clock::now() < deadline) {
			char type = 0;
			std::vector<uint8_t> buffer;
			c.readMessage(type, buffer);
			if (type == PgConnection::ERROR_RESPONSE) { errored = true; continue; }
			if (type == PgConnection::READY_FOR_QUERY) break;
		}
		r.client_ok = !errored;
		// Still connected here on purpose: once this client disconnects, session teardown drops
		// the backend connection whether or not the resync disowned it.
		r.pool_live = pooledConnsWithin(admin, r.pool_baseline, 5);
	} catch (const PgException& e) {
		r.detail = std::string("frame threw: ") + e.what();
	}
	const std::string seq_after = seqValue(be_db);
	r.insert_ran = (!seq_before.empty() && seq_after != seq_before);
	r.kill_fired = killedWithin(be_db, kill_before, 5);
	r.row_visible = insertVisible(be_db, marker);
	r.gauge_after = connectedGaugeWithin(admin, r.gauge_baseline, 15);

	// Bystander: a fresh client on the same hostgroup must get a healthy connection, not
	// whatever the failed resync would have left behind had it been pooled.
	try {
		PgConnection bystander(5000);
		bystander.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
		bystander.execute("SELECT 1");
		bystander.waitForReady();
		r.bystander_ok = true;
	} catch (const PgException&) {
		r.bystander_ok = false;
	}

	if (r.detail == "not run") {
		r.detail = std::string("client_ok=") + (r.client_ok ? "yes" : "no")
			+ ", insert_ran=" + (r.insert_ran ? "yes" : "no")
			+ ", kill_fired=" + (r.kill_fired ? "yes" : "no")
			+ ", row_visible=" + (r.row_visible ? "yes" : "no")
			+ ", gauge " + std::to_string(r.gauge_baseline) + " -> " + std::to_string(r.gauge_after)
			+ ", pooled while connected " + std::to_string(r.pool_baseline) + " -> " + std::to_string(r.pool_live)
			+ ", bystander_ok=" + (r.bystander_ok ? "yes" : "no");
	}
	return r;
}

int main(int, char**) {
	plan(87);
	if (cl.getEnv()) return exit_status();

	auto admin = adminConn();
	if (!admin || PQstatus(admin.get()) != CONNECTION_OK) BAIL_OUT("no admin connection");
	auto be = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                   cl.pgsql_server_username, cl.pgsql_server_password, "postgres");
	if (!be || PQstatus(be.get()) != CONNECTION_OK) BAIL_OUT("no direct backend connection");

	const std::string base = "orphsync_probe_" + std::to_string((long)getpid());
	std::vector<std::string> stranded;   // terminated in teardown

	// The write probe lives in the database the CLIENT connects to, which is named after the user.
	// Created up front because the read frames use its sequence too, to show whether their Execute ran.
	auto be_db = openConn(cl.pgsql_server_host, cl.pgsql_server_port,
	                      cl.pgsql_server_username, cl.pgsql_server_password, cl.pgsql_username);
	if (!be_db || PQstatus(be_db.get()) != CONNECTION_OK)
		BAIL_OUT("no direct connection to the client's own database");

	exec(be_db.get(), "DROP TABLE IF EXISTS orphsync_t");
	exec(be_db.get(), "DROP SEQUENCE IF EXISTS orphsync_seq");
	exec(be_db.get(), "DROP SEQUENCE IF EXISTS orphsync_kill_seq");
	if (!exec(be_db.get(), "CREATE TABLE orphsync_t (v text)")
	    || !exec(be_db.get(), "CREATE SEQUENCE orphsync_seq")
	    || !exec(be_db.get(), "CREATE SEQUENCE orphsync_kill_seq"))
		BAIL_OUT("could not create the write probe");

	// The resync-failure scenario needs the backend to die at one exact moment: while ProxySQL is
	// waiting on the Sync it sent to conclude the batch. That Sync is what commits the implicit
	// transaction, and a DEFERRABLE INITIALLY DEFERRED constraint trigger runs at commit and
	// nowhere else -- so the backend kills itself from inside the commit, with no timing to race.
	// The kill sequence is bumped first because a sequence is not rolled back: it still says the
	// trigger ran after the aborted transaction has taken everything else with it. SECURITY
	// DEFINER so the frontend user needs no rights of its own. The WHEN clause keeps every other
	// scenario's writes out of it.
	if (!exec(be_db.get(),
		"CREATE OR REPLACE FUNCTION orphsync_selfkill() RETURNS trigger AS $$ BEGIN "
		"PERFORM nextval('orphsync_kill_seq'); "
		"PERFORM pg_terminate_backend(pg_backend_pid()); RETURN NULL; END $$ "
		"LANGUAGE plpgsql SECURITY DEFINER")
	    || !exec(be_db.get(),
		"CREATE CONSTRAINT TRIGGER orphsync_selfkill_trg AFTER INSERT ON orphsync_t "
		"DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.v LIKE '%_resyncfail_%') "
		"EXECUTE FUNCTION orphsync_selfkill()"))
		BAIL_OUT("could not create the resync-failure trigger");
	exec(be_db.get(), std::string("GRANT ALL ON orphsync_t TO ") + cl.pgsql_username);
	exec(be_db.get(), std::string("GRANT USAGE ON SEQUENCE orphsync_seq TO ") + cl.pgsql_username);

	// --- libpq path: the control. --------------------------------------------------------------
	// Establishes that the frame is well-formed and that failing the Describe locally is the
	// intended answer, so anything the native scenario does differently is about the backend leg.
	const std::string marker_libpq = base + "_libpq";
	setNativeMode(admin.get(), false);
	const Probe p_libpq = runOrphanedSyncFrame(be.get(), marker_libpq);
	if (!p_libpq.stranded_pid.empty()) stranded.push_back(p_libpq.stranded_pid);
	diag("libpq: %s", p_libpq.detail.c_str());

	ok(p_libpq.client_rejected,
	   "libpq: ProxySQL answers the unknown Describe itself [%s]", p_libpq.detail.c_str());
	clearStranded(be_db.get(), p_libpq.stranded_pid);
	ok(p_libpq.stranded_pid.empty(),
	   "libpq: no backend session is left holding an open transaction after the frame is dropped [%s]",
	   p_libpq.detail.c_str());

	// --- native path: the case under test. -----------------------------------------------------
	const std::string marker_native = base + "_native";
	setNativeMode(admin.get(), true);
	const std::string seq_before_native = execScalar(be_db.get(), "SELECT last_value::text FROM orphsync_seq");
	const Probe p_native = runOrphanedSyncFrame(be.get(), marker_native);
	const std::string seq_after_native = execScalar(be_db.get(), "SELECT last_value::text FROM orphsync_seq");
	diag("native read frame: sequence %s -> %s (moved = its Execute ran on the backend)",
	     seq_before_native.c_str(), seq_after_native.c_str());
	if (!p_native.stranded_pid.empty()) stranded.push_back(p_native.stranded_pid);
	diag("native: %s", p_native.detail.c_str());

	ok(p_native.client_rejected,
	   "native: ProxySQL answers the unknown Describe itself [%s]", p_native.detail.c_str());
	clearStranded(be_db.get(), p_native.stranded_pid);
	ok(p_native.stranded_pid.empty(),
	   "native: no backend session is left holding an open transaction after the frame is dropped -- "
	   "the discarded Sync must not leave the backend mid-batch with its locks held [%s]",
	   p_native.detail.c_str());

	// --- does a refused frame commit a write the client was told had failed? --------------------
	// Run on BOTH paths. This is where the fix matters most and where getting it wrong is worst:
	// finishing the batch would make the row durable after the client was told the batch failed.
	const WriteProbe w_libpq = runWriteScenario(admin.get(), be_db.get(), base + "_write_libpq",
	                                            false, "libpq");
	reportWrite("libpq", w_libpq);

	const WriteProbe w_native = runWriteScenario(admin.get(), be_db.get(), base + "_write_native",
	                                             true, "native");
	reportWrite("native", w_native);

	// --- ordinary traffic must be untouched ------------------------------------------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);
		const std::string m = base + "_ok_" + label;
		const HealthyProbe h = runHealthyFrame(be_db.get(), m, false);
		diag("%s healthy frame: %s", label, h.detail.c_str());
		ok(h.completed, "%s: an ordinary extended-query frame still succeeds [%s]", label, h.detail.c_str());
		ok(h.conn_survived,
		   "%s: an ordinary frame's backend connection is NOT discarded -- the discard must fire only "
		   "on a refused frame, not on every extended query [%s]", label, h.detail.c_str());
	}

	// --- the refused mark must not leak into the next frame --------------------------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);
		const std::string m = base + "_after_" + label;
		const HealthyProbe h = runHealthyFrame(be_db.get(), m, true);
		diag("%s healthy-after-refused frame: %s", label, h.detail.c_str());
		ok(h.completed,
		   "%s: a healthy frame sent after a refused one on the same session still succeeds [%s]",
		   label, h.detail.c_str());
		ok(h.conn_survived,
		   "%s: and its connection is NOT discarded -- the refused mark is cleared when the next "
		   "frame starts, or every frame after a refusal would lose its connection [%s]",
		   label, h.detail.c_str());
	}

	// --- a refused frame inside an explicit transaction ------------------------------------------
	setNativeMode(admin.get(), true);
	std::string tx_detail = "not run";
	const bool tx_ok = explicitTxnNotSilentlyLost(be_db.get(), base + "_tx", tx_detail);
	diag("native explicit-transaction scenario: %s", tx_detail.c_str());
	ok(tx_ok,
	   "native: a client's explicit transaction must not be silently lost by the discard -- a write "
	   "issued after the refused frame must not survive the client's own ROLLBACK [%s]",
	   tx_detail.c_str());

	// --- a refused frame on a POOLED connection, and the next client after it --------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);          // drains the pool ...
		warmPool(base + "_warm_" + label);                // ... and this puts one back in it

		const std::string m = base + "_pooled_" + label;
		std::string d = "not run";
		const std::string seq_before = seqValue(be_db.get());
		std::string seq_live = seq_before;
		bool visible_live = false;
		const bool rejected = runAbandonedWriteFrame(m, d, be_db.get(), &seq_live, &visible_live);
		const std::string stranded = strandedBackendPid(be.get(), m);
		diag("%s pooled-connection refused frame: %s, sequence %s -> %s, stranded pid=%s",
		     label, d.c_str(), seq_before.c_str(), seq_live.c_str(),
		     stranded.empty() ? "none" : stranded.c_str());

		ok(rejected, "%s: a refused frame on a REUSED pooled connection is still rejected [%s]",
		   label, d.c_str());
		ok(stranded.empty(),
		   "%s: and it leaves no backend holding an open transaction -- every other scenario here "
		   "runs on a fresh connection, so this is the only one covering the ordinary case [stranded=%s]",
		   label, stranded.empty() ? "none" : stranded.c_str());
		clearStranded(be_db.get(), stranded);

		// Now the bystander: whatever that refused frame left behind must not reach the next client.
		std::string bd = "not run";
		const bool bystander_ok = bystanderUnaffected(be_db.get(), base + "_bystander_" + label, bd);
		diag("%s bystander: %s", label, bd.c_str());
		ok(bystander_ok,
		   "%s: the NEXT client does not inherit an open transaction from the refused frame -- its "
		   "own write autocommits and is visible at once, which it would not be inside someone "
		   "else's transaction [%s]", label, bd.c_str());
	}

	// --- a frame the BACKEND rejects keeps its connection -----------------------------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);
		const std::string m = base + "_bkerr_" + label;
		const HealthyProbe h = runBackendErrorFrame(be_db.get(), m);
		diag("%s backend-error frame: %s", label, h.detail.c_str());
		ok(h.completed, "%s: the backend rejects the frame, so the error came from PostgreSQL and not "
		   "from ProxySQL [%s]", label, h.detail.c_str());
		ok(h.conn_survived,
		   "%s: and its connection is KEPT, not discarded -- PostgreSQL already poisoned that batch, "
		   "so finishing it rolls back and the connection is still good. Discarding here would throw "
		   "one away on every failed query [%s]", label, h.detail.c_str());
	}

	// --- a backend error on a FLUSH-terminated step: the injected Sync ----------------------------
	// The block above fails on 1/0, which PostgreSQL only discovers while EXECUTING -- and the
	// Execute is the frame's last message, so it carries the client's Sync and the backend answers
	// with ReadyForQuery by itself. Nothing there has to be recovered.
	//
	// Fail the PARSE instead and the picture changes. Bind and Execute still follow it, so the Parse
	// goes out Flush-terminated, and after an error on a Flush-terminated message PostgreSQL sends no
	// ReadyForQuery at all until it sees a Sync. ProxySQL has to manufacture one.
	//
	// That is why `ready` is the assertion that matters here: on this frame a ReadyForQuery can only
	// exist because ProxySQL injected the Sync that produced it. Both paths are run because the
	// libpq path reaches the same place by a different route, and a difference between them is worth
	// knowing about.
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);
		const std::string m = base + "_resync_" + label;
		const FlushResyncProbe p = runFlushTerminatedParseError(be_db.get(), m, false);
		diag("%s flush-terminated parse error: %s", label, p.detail.c_str());
		ok(p.errored && p.sqlstate == "42P01",
		   "%s: the Parse fails on the BACKEND (SQLSTATE 42P01) -- an error raised inside ProxySQL "
		   "would never put the backend in the aborted-until-Sync state this scenario is about, and "
		   "the rest of it would prove nothing [%s]", label, p.detail.c_str());
		ok(p.got_ready,
		   "%s: a ReadyForQuery still reaches the client -- PostgreSQL sends none of its own after an "
		   "error on a Flush-terminated message, so this one exists only because ProxySQL injected a "
		   "Sync. Without it the client waits for the query timeout [%s]", label, p.detail.c_str());
		ok(p.followup_ok,
		   "%s: and the SAME connection serves the next query -- resynchronising is only worth doing "
		   "if the connection is usable afterwards, not merely if the client was told something [%s]",
		   label, p.detail.c_str());
	}

	// --- the same error inside an explicit transaction --------------------------------------------
	// Sync concludes the batch; it does NOT close a transaction the client opened with BEGIN.
	// PostgreSQL's protocol documentation says so outright and points at the ReadyForQuery status
	// byte as the way to tell. So the connection comes back synchronised but still inside a
	// transaction, and that transaction is aborted. ProxySQL has to notice: a connection in that
	// state belongs to this client until it ends the transaction, and must never go back to the pool
	// for somebody else to draw.
	{
		setNativeMode(admin.get(), true);
		const std::string m = base + "_resync_tx";
		const FlushResyncProbe p = runFlushTerminatedParseError(be_db.get(), m, true);
		diag("native flush-terminated parse error inside BEGIN: %s", p.detail.c_str());
		ok(p.errored && p.sqlstate == "42P01",
		   "native/txn: the Parse fails on the backend inside the transaction [%s]", p.detail.c_str());
		ok(p.got_ready && p.rfq_status == 'E',
		   "native/txn: the injected Sync's ReadyForQuery reports a FAILED transaction block ('E') "
		   "rather than idle -- the Sync ended the batch but left the BEGIN open, and that status "
		   "byte is the only thing that says so [%s]", p.detail.c_str());
		ok(!p.followup_ok && p.followup_sqlstate == "25P02",
		   "native/txn: the next statement is refused with 25P02 -- proof the aborted transaction is "
		   "still there and the connection was not quietly reset, nor handed to anyone else [%s]",
		   p.detail.c_str());
		ok(p.rollback_ok && p.after_rollback_ok,
		   "native/txn: ROLLBACK ends it and the connection returns to normal service [%s]",
		   p.detail.c_str());
	}

	// --- the same discard, reached by two other routes -------------------------------------------
	struct Route { const char* name; const char* sql; };
	// COPY is here because of what runs AFTER the frame is thrown away, not just how it is thrown
	// away: that path calls finishQuery() on the spot, and finishQuery dereferences the backend
	// connection the discard has just destroyed. Without this scenario that is a crash nothing here
	// would see.
	// Each entry is a different statement ProxySQL refuses on its own, inside a frame whose earlier
	// Execute has already run on the backend. They leave by different exits -- some through
	// finishQuery() on the spot, some through RequestEnd with no data stream -- and the point of
	// listing them is that the outcome has to be the same however they leave: the write the client
	// was told failed must not survive.
	const Route routes[] = {
		{ "discard",  "DISCARD ALL" },
		{ "copy",     "COPY orphsync_t (v) FROM STDIN" },
		{ "resetall", "RESET ALL" },
		{ "badparam", "SET DateStyle TO 'INVALID_STYLE'" },
	};
	for (const Route& r : routes) {
		for (int native = 0; native <= 1; native++) {
			const char* label = native ? "native" : "libpq";
			const std::string m = base + "_" + r.name + "route_" + label;
			const WriteProbe w = runRefusedStatementScenario(admin.get(), be_db.get(), m,
			                                                 native != 0, label, r.sql, r.name);
			ok(w.rejected, "%s: a frame refused because '%s' cannot run inside it is rejected at the "
			   "client -- a different route into the discard than the rest of this file [%s]",
			   label, r.sql, w.detail.c_str());
			ok(w.reached, "%s: and the %s-route frame's Execute DID run on the backend, so the row "
			   "being absent below means something [sequence moved=%s]",
			   label, r.name, w.reached ? "YES" : "no");
			ok(!w.visible_live && !w.visible_after,
			   "%s: the %s-route frame's write is NOT committed, and the session survived the "
			   "discard -- every route that throws a frame away has to reach the same outcome "
			   "[visible live=%s, after=%s]",
			   label, r.name, w.visible_live ? "YES" : "no", w.visible_after ? "YES" : "no");
			clearStranded(be.get(), strandedBackendPid(be_db.get(), m));
		}
	}

	// --- refusing frames must not leak pool slots ------------------------------------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);   // drains the pool, so the baseline is a clean one
		const long gauge_baseline = connectedGauge(admin.get());
		bool reached = false;
		const bool rejected = runLeakRounds(base + "_" + label, be_db.get(), &reached);
		const long gauge_end = connectedGaugeWithin(admin.get(), gauge_baseline, 15);
		// gauge_baseline >= 0 is not decoration: both reads return -1 if the admin query fails, and
		// -1 == -1 would pass this while measuring nothing at all. `reached` is the other half of
		// that: zero to zero also describes rounds that never opened a backend connection.
		ok(rejected && reached && gauge_baseline >= 0 && gauge_end == gauge_baseline,
		   "%s: %d refused frames in a row leave the connected-backend count where it started -- "
		   "discarding a connection per refusal is exactly how pool slots leak [baseline=%ld, "
		   "end=%ld, all rejected=%s, reached a backend=%s]",
		   label, DISCARD_LEAK_ROUNDS, gauge_baseline, gauge_end, rejected ? "yes" : "no",
		   reached ? "yes" : "no");
	}

	// --- a SUCCEEDED frame whose Sync never reached the backend (PJ1) ----------------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);
		const std::string m = base + "_resync_" + label;
		const ResyncProbe r = runLocallyClosedSyncFrame(admin.get(), be_db.get(), m);
		diag("%s locally-closed-Sync frame: %s", label, r.detail.c_str());
		ok(r.proxy_alive,
		   "%s: the proxy is still alive after a frame whose trailing Close is answered locally -- "
		   "before the fix, native's resync path aborted the WHOLE PROCESS here [%s]",
		   label, r.detail.c_str());
		ok(r.completed, "%s: the frame itself completes with no error, exactly as the client was told [%s]",
		   label, r.detail.c_str());
		ok(!r.stranded, "%s: and no backend session is left mid-batch afterwards [%s]",
		   label, r.detail.c_str());
		ok(r.seq_moved, "%s: the Execute really ran on the backend -- without this, the row being "
		   "present below would prove nothing [%s]", label, r.detail.c_str());
		ok(r.row_visible,
		   "%s: the write DOES commit -- the client was already told this frame SUCCEEDED "
		   "(CommandComplete, CloseComplete, ReadyForQuery), so concluding the batch is what it "
		   "asked for; discarding the connection instead would roll back a write it believes "
		   "already went through [%s]", label, r.detail.c_str());
		clearStranded(be_db.get(), strandedBackendPid(be_db.get(), m));
	}

	// --- the resync ITSELF fails: the backend is already gone (PJ1 addendum) --------------------
	for (int native = 0; native <= 1; native++) {
		const char* label = native ? "native" : "libpq";
		setNativeMode(admin.get(), native != 0);
		const std::string m = base + "_resyncfail_" + label;
		const ResyncFailureProbe r = runResyncFailure(admin.get(), be_db.get(), m);
		diag("%s resync-failure frame: %s", label, r.detail.c_str());
		ok(r.client_ok, "%s: the client's own frame still completes cleanly -- the Close is "
		   "answered locally regardless of the backend's fate [%s]", label, r.detail.c_str());
		ok(r.insert_ran, "%s: the Execute really ran on the backend before it was killed -- "
		   "without this the rest of this probe would prove nothing [%s]", label, r.detail.c_str());
		ok(r.kill_fired, "%s: the resync's Sync reached the backend and killed it -- the commit "
		   "trigger only runs when the batch is concluded, so without this the whole scenario is "
		   "an ordinary successful frame [%s]", label, r.detail.c_str());
		ok(r.gauge_after == r.gauge_baseline,
		   "%s: the connected-backend count returns to baseline -- a resync that fails must "
		   "destroy the connection, not report success and leave a dead one counted as pooled "
		   "[%s]", label, r.detail.c_str());
		ok(r.pool_live == r.pool_baseline,
		   "%s: and the hostgroup is left holding no connection while the client is still there -- "
		   "a resync that fails must destroy it, not leave a dead one in ConnFree for the next "
		   "client to draw [%s]", label, r.detail.c_str());
		ok(r.bystander_ok, "%s: and a fresh client on the same hostgroup gets a healthy "
		   "connection, not whatever a wrongly-pooled dead one would have handed it [%s]",
		   label, r.detail.c_str());
	}

	exec(be_db.get(), "DROP TABLE IF EXISTS orphsync_t");
	exec(be_db.get(), "DROP SEQUENCE IF EXISTS orphsync_seq");
	exec(be_db.get(), "DROP SEQUENCE IF EXISTS orphsync_kill_seq");

	// A stranded session holds its locks until something closes it, so it would block whatever runs
	// next. Terminate it here rather than leaving that for the following test to trip over.
	for (const std::string& pid : stranded) {
		diag("terminating stranded backend pid %s", pid.c_str());
		exec(be.get(), "SELECT pg_terminate_backend(" + pid + ")");
	}
	setNativeMode(admin.get(), false);
	return exit_status();
}
