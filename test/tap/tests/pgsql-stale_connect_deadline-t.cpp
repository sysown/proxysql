#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "pgsql_native_tier.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int BACKEND_HG = 0;

// The deadline the defect arms. Small enough that the test does not wait on
// it, large enough that nothing legitimate races it: the only real connect it
// can govern here is a localhost backend.
static const int CONNECT_TIMEOUT_MAX_MS = 1000;
// The reset's DISCARD ALL is blocked by the helper's share lock on pg_depend,
// so any value above the statement's startup latency kills it; 100ms leaves
// scheduler jitter room while still returning promptly.
static const int RESET_STATEMENT_TIMEOUT_MS = 100;

static void silenceNotices(void*, const char*) {}

static PGConnPtr openConn(const char* h, int p, const char* u, const char* pw, const char* db) {
    std::stringstream ss;
    ss << "host=" << h << " port=" << p << " user=" << u << " password=" << pw;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=disable connect_timeout=10";
    PGConnPtr c(PQconnectdb(ss.str().c_str()), &PQfinish);
    if (c) PQsetNoticeProcessor(c.get(), &silenceNotices, nullptr);
    return c;
}

static PGConnPtr openClient() {
    return openConn(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_password, cl.pgsql_username);
}

static PGConnPtr openAdmin() {
    return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, "");
}

// The helper locks a per-database catalog, so it must land in the database the
// proxied sessions use, not in the privileged role's default one.
static PGConnPtr openHelper() {
    return openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username,
                    cl.pgsql_server_password, cl.pgsql_username);
}

static bool execOk(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    const bool ok = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!ok) diag("%s failed: %s", q.c_str(), PQerrorMessage(c));
    PQclear(r);
    return ok;
}

static std::string scalar(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    std::string out;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
        out = PQgetvalue(r, 0, 0);
    PQclear(r);
    return out;
}

static std::string trimmed(std::string s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

// ProxySQL's view of how many connections sit unused in a hostgroup's pool.
// SUM, not a single row: the hostgroup may contain more than one server.
static int poolFree(PGconn* admin, int hg) {
    const std::string n = scalar(admin,
        "SELECT COALESCE(SUM(ConnFree),0) FROM stats.stats_pgsql_connection_pool WHERE hostgroup="
        + std::to_string(hg));
    return n.empty() ? -1 : atoi(n.c_str());
}

// The pool fills and drains asynchronously: a client disconnect, a LOAD that
// drops connections and a killed backend all land some milliseconds after the
// statement returns. Sampling once reads whatever the worker threads happen
// not to have finished yet.
static int poolFreeWithin(PGconn* admin, int hg, int want, int seconds) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    int last = -1;
    while (true) {
        last = poolFree(admin, hg);
        if (last == want || std::chrono::steady_clock::now() >= deadline) return last;
        usleep(100000);
    }
}

static bool flushPool(PGconn* admin) {
    const std::string hg = std::to_string(BACKEND_HG);
    // Put back the status the row actually had; assuming ONLINE would quietly
    // promote a server the harness left in another state.
    std::string prev = scalar(admin, "SELECT status FROM pgsql_servers WHERE hostgroup_id=" + hg + " LIMIT 1");
    if (prev.empty()) prev = "ONLINE";
    if (!execOk(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)) return false;
    if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    const int emptied = poolFreeWithin(admin, BACKEND_HG, 0, 10);
    if (!execOk(admin, "UPDATE pgsql_servers SET status='" + prev + "' WHERE hostgroup_id=" + hg)) return false;
    if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    return emptied == 0;
}

// Run one statement through a proxied session; report success, SQLSTATE and
// message so failures can say exactly what the client saw.
static bool runClientQuery(PGconn* c, const char* q, std::string& sqlstate, std::string& msg) {
    PGresult* r = PQexec(c, q);
    const ExecStatusType st = PQresultStatus(r);
    const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
    sqlstate = s ? s : "";
    msg = trimmed(PQresultErrorMessage(r));
    PQclear(r);
    return (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
}

int main(int, char**) {
    plan(9);
    if (cl.getEnv()) return exit_status();

    auto admin = openAdmin();
    ok(admin && PQstatus(admin.get()) == CONNECTION_OK, "ADMIN connection created%s",
       admin ? "" : " (null)");
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) return exit_status();

    // ---- runtime state, restored in memory only -- never SAVE ... TO DISK ----
    const std::string saved_ctmax = scalar(admin.get(),
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-connect_timeout_server_max'");
    const bool native_supported = pgsql_native_supported(admin.get());
    const std::string saved_native = native_supported
        ? scalar(admin.get(),
            "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'")
        : std::string();

    auto cleanup = [&]() {
        if (!saved_ctmax.empty()) {
            execOk(admin.get(), "SET pgsql-connect_timeout_server_max=" + saved_ctmax);
            execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
        }
        if (!saved_native.empty()) {
            execOk(admin.get(), "SET pgsql-use_native_backend_protocol=" + saved_native);
            execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME");
        }
    };

    if (!execOk(admin.get(), "SET pgsql-connect_timeout_server_max=" + std::to_string(CONNECT_TIMEOUT_MAX_MS))
        || !execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
        cleanup();
        BAIL_OUT("cannot set pgsql-connect_timeout_server_max");
    }
    if (native_supported
        && (!execOk(admin.get(), "SET pgsql-use_native_backend_protocol='false'")
            || !execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"))) {
        cleanup();
        BAIL_OUT("cannot select the libpq backend protocol");
    }

    // Start from an empty pool so the poisoned connection is the only one in
    // it: anything left over would serve the pickup instead.
    const bool flushed = flushPool(admin.get());
    ok(flushed, "hostgroup %d starts with no pooled connection (ConnFree=%d)",
       BACKEND_HG, poolFree(admin.get(), BACKEND_HG));
    if (!flushed) {
        cleanup();
        BAIL_OUT("cannot flush the backend pool");
    }

    // ---- session A: poison exactly one pooled connection -------------------
    {
        auto a = openClient();
        if (!a || PQstatus(a.get()) != CONNECTION_OK) {
            cleanup();
            BAIL_OUT("session A: client connection failed");
        }
        const bool poisoned =
            execOk(a.get(), "SET bytea_output = 'escape'")
            && execOk(a.get(),
                  "DO $$ BEGIN EXECUTE format('CREATE TEMP TABLE stale_deadline_t_pad_%s AS SELECT 1', 1); END $$")
            && execOk(a.get(),
                  "SELECT set_config('statement_timeout', '"
                  + std::to_string(RESET_STATEMENT_TIMEOUT_MS) + "', false)");
        if (!poisoned) {
            cleanup();
            BAIL_OUT("session A: could not poison the connection");
        }
        // The disconnect returns the connection to the pool still carrying the
        // variable, the temp table and the timeout.
    }
    const int poisoned_pooled = poolFreeWithin(admin.get(), BACKEND_HG, 1, 10);
    ok(poisoned_pooled == 1,
       "session A left exactly one poisoned connection in the pool (ConnFree=%d)", poisoned_pooled);
    if (poisoned_pooled != 1) {
        cleanup();
        BAIL_OUT("the poisoned connection was not pooled; the scenario cannot proceed");
    }

    // ---- helper: the catalog lock the reset will block on ------------------
    // Needs a role allowed to LOCK a system catalog; the harness's direct
    // backend role is that. lock_timeout bounds the wait so an unexpected
    // conflicting holder fails this setup loudly instead of hanging the test.
    auto helper = openHelper();
    bool helper_locked = false;
    std::string lock_state;
    if (helper && PQstatus(helper.get()) == CONNECTION_OK) {
        helper_locked = execOk(helper.get(), "BEGIN")
            && execOk(helper.get(), "SET LOCAL lock_timeout = '5s'")
            && execOk(helper.get(), "LOCK TABLE pg_depend IN SHARE MODE");
        if (helper_locked)
            lock_state = scalar(helper.get(),
                "SELECT mode || ' granted=' || granted FROM pg_locks"
                " WHERE locktype = 'relation' AND relation = 'pg_depend'::regclass AND pid = pg_backend_pid()");
    }
    ok(helper_locked && lock_state.find("ShareLock") != std::string::npos
           && lock_state.find("granted=t") != std::string::npos,
       "helper holds a share lock on pg_depend in the proxied database (got '%s')",
       lock_state.c_str());
    if (!helper_locked) {
        // BAIL_OUT exits without running destructors; the socket close rolls
        // the helper's transaction back and releases the lock.
        cleanup();
        BAIL_OUT("cannot take the pg_depend share lock");
    }

    // ---- session B, query 1: the pickup and the blocked reset ----------------
    // The reset runs ON this session; its DISCARD ALL blocks on the helper's
    // lock and is cancelled by the statement timeout session A armed. The
    // client seeing that 57014 IS the leak branch: the alternative branch
    // (backend connection unusable) retries on a fresh connection and the
    // client would see a result instead of the cancellation.
    auto b = openClient();
    if (!b || PQstatus(b.get()) != CONNECTION_OK) {
        cleanup();
        BAIL_OUT("session B: client connection failed");
    }
    std::string b1_sqlstate, b1_msg;
    const bool b1_ok = runClientQuery(b.get(), "SELECT 'B1'", b1_sqlstate, b1_msg);
    diag("session B, first query: ok=%d sqlstate=%s error='%s'",
         (int)b1_ok, b1_sqlstate.c_str(), b1_msg.c_str());
    ok(!b1_ok && (b1_sqlstate == "57014"
           || b1_msg.find("canceling statement due to statement timeout") != std::string::npos),
       "session B's first query surfaces the failed connection reset as a 57014 cancellation");

    // The failed reset must not quietly pool the connection again.
    const int drained = poolFreeWithin(admin.get(), BACKEND_HG, 0, 10);
    ok(drained == 0, "the poisoned connection was destroyed, not reset and pooled (ConnFree=%d)", drained);

    // The lock has done its job; the backend is fully healthy from here on.
    execOk(helper.get(), "COMMIT");

    // ---- session B, query 2: past the deadline window ----------------------
    // The deadline was armed when query 1's reset started, so sleeping past
    // pgsql-connect_timeout_server_max after query 1 puts this query beyond
    // it. Nothing is wrong with the hostgroup, so this must succeed: a
    // deadline left armed by the failed reset is refused with
    // "Max connect timeout reached while reaching hostgroup ... after 0ms".
    usleep((CONNECT_TIMEOUT_MAX_MS + 750) * 1000);
    std::string b2_sqlstate, b2_msg;
    const bool b2_ok = runClientQuery(b.get(), "SELECT 'B2'", b2_sqlstate, b2_msg);
    if (!b2_ok)
        diag("session B, second query: sqlstate=%s error='%s'", b2_sqlstate.c_str(), b2_msg.c_str());
    ok(b2_ok, "session B's next query, after the deadline window on a healthy hostgroup, succeeds");

    // ---- session B, query 3: the session must be usable either way -----------
    // The previous query was either served or refused by give_up_waiting(),
    // which clears the deadline on its way out. Either way the session owes
    // its client working queries now.
    std::string b3_sqlstate, b3_msg;
    const bool b3_ok = runClientQuery(b.get(), "SELECT 'B3'", b3_sqlstate, b3_msg);
    if (!b3_ok)
        diag("session B, third query: sqlstate=%s error='%s'", b3_sqlstate.c_str(), b3_msg.c_str());
    ok(b3_ok, "session B works again on the query after the deadline incident");

    // ---- control: the backend and hostgroup were healthy all along -----------
    {
        auto c = openClient();
        std::string c_sqlstate, c_msg;
        const bool c_ok = c && PQstatus(c.get()) == CONNECTION_OK
            && runClientQuery(c.get(), "SELECT 'control'", c_sqlstate, c_msg);
        if (!c_ok)
            diag("control session: sqlstate=%s error='%s'", c_sqlstate.c_str(), c_msg.c_str());
        ok(c_ok, "a fresh session works at the same moment, so the hostgroup was healthy");
    }

    cleanup();
    return exit_status();
}
