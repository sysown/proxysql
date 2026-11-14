#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
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

// Owns run-unique SQLite temp snapshots of everything this test mutates.
// restore() rolls runtime and memory back independently, then drops only the
// snapshots this run created; any failed step retains them for a retry.
struct StateGuard {
    std::string mem_servers;
    std::string rt_servers;
    std::string mem_vars;
    std::string rt_vars;
    std::vector<std::string> owned;
    PGconn* admin = nullptr;
    bool dirty = false;

    StateGuard() = default;
    StateGuard(const StateGuard&) = delete;
    StateGuard& operator=(const StateGuard&) = delete;

    bool capture(PGconn* a) {
        admin = a;
        const std::string base = "stale_deadline_" + std::to_string(getpid()) + "_"
            + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        mem_servers = "temp." + base + "_mem_servers";
        rt_servers = "temp." + base + "_rt_servers";
        mem_vars = "temp." + base + "_mem_vars";
        rt_vars = "temp." + base + "_rt_vars";
        const struct { const std::string* name; const char* query; } copies[] = {
            { &mem_servers, "SELECT * FROM pgsql_servers" },
            { &rt_servers, "SELECT * FROM runtime_pgsql_servers" },
            { &mem_vars, "SELECT * FROM global_variables WHERE variable_name LIKE 'pgsql-%'" },
            { &rt_vars, "SELECT * FROM runtime_global_variables WHERE variable_name LIKE 'pgsql-%'" },
        };
        for (const auto& c : copies) {
            if (!execOk(admin, "CREATE TEMP TABLE " + *c.name + " AS " + c.query)) {
                diag("snapshot capture incomplete before any mutation");
                return false;
            }
            owned.push_back(*c.name);
        }
        dirty = true;
        return true;
    }

    bool drop_owned() {
        bool all_ok = true;
        for (auto it = owned.begin(); it != owned.end();) {
            if (execOk(admin, "DROP TABLE IF EXISTS " + *it)) {
                it = owned.erase(it);
            } else {
                diag("snapshot cleanup failed; retaining %s", it->c_str());
                all_ok = false;
                ++it;
            }
        }
        return all_ok;
    }

    bool restore() {
        if (!admin) return true;
        if (dirty) {
            // Stage the original runtime configuration into memory first.
            bool staged = true;
            staged = execOk(admin, "DELETE FROM pgsql_servers") && staged;
            staged = execOk(admin, "INSERT INTO pgsql_servers SELECT * FROM " + rt_servers) && staged;
            staged = execOk(admin, "INSERT OR REPLACE INTO global_variables SELECT * FROM " + rt_vars) && staged;
            bool runtime_ok = staged;
            if (staged) {
                runtime_ok = execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME") && runtime_ok;
                runtime_ok = execOk(admin, "LOAD PGSQL VARIABLES TO RUNTIME") && runtime_ok;
            }
            // Restore memory last, without a LOAD, even if runtime failed.
            bool memory_ok = true;
            memory_ok = execOk(admin, "DELETE FROM pgsql_servers") && memory_ok;
            memory_ok = execOk(admin, "INSERT INTO pgsql_servers SELECT * FROM " + mem_servers) && memory_ok;
            memory_ok = execOk(admin, "INSERT OR REPLACE INTO global_variables SELECT * FROM " + mem_vars) && memory_ok;
            if (!runtime_ok || !memory_ok) {
                diag("state restore incomplete; keeping snapshots for retry (runtime=%d memory=%d)",
                     (int)runtime_ok, (int)memory_ok);
                return false;
            }
            dirty = false; // Configuration restored; only drops remain.
        }
        return drop_owned();
    }

    const std::string& servers_snapshot() const { return mem_servers; }

    ~StateGuard() noexcept {
        if (!admin || (!dirty && owned.empty())) return;
        try {
            if (!restore()) diag("StateGuard fallback: state restore incomplete");
        } catch (...) {
            diag("StateGuard fallback: state restore threw");
        }
    }
};

static bool flushPool(PGconn* admin, const StateGuard& guard) {
    const std::string hg = std::to_string(BACKEND_HG);
    // Take the whole hostgroup offline so every pooled connection is dropped.
    if (!execOk(admin, "UPDATE pgsql_servers SET status='OFFLINE_HARD' WHERE hostgroup_id=" + hg)) return false;
    if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    const int emptied = poolFreeWithin(admin, BACKEND_HG, 0, 10);
    // Restore every original per-row memory setting, not one LIMIT 1 status.
    if (!execOk(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg)) return false;
    if (!execOk(admin, "INSERT INTO pgsql_servers SELECT * FROM " + guard.servers_snapshot()
            + " WHERE hostgroup_id=" + hg)) return false;
    if (!execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    return emptied == 0;
}

[[noreturn]] static void cleanup_and_bail(StateGuard& guard, const char* why) {
    if (!guard.restore()) diag("%s: cleanup incomplete; snapshots retained for retry", why);
    BAIL_OUT("%s", why);
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
    plan(10);
    if (cl.getEnv()) return exit_status();

    auto admin = openAdmin();
    ok(admin && PQstatus(admin.get()) == CONNECTION_OK, "ADMIN connection created%s",
       admin ? "" : " (null)");
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) return exit_status();

    const bool native_supported = pgsql_native_supported(admin.get());

    // Snapshot runtime and memory before the first SET/LOAD/OFFLINE_HARD.
    StateGuard guard;
    if (!guard.capture(admin.get()))
        cleanup_and_bail(guard, "cannot snapshot the pgsql configuration");

    // The reset scenario requires an untracked timeout on a pooled connection.
    if (!execOk(admin.get(), "SET pgsql-connect_timeout_server_max=" + std::to_string(CONNECT_TIMEOUT_MAX_MS))
        || !execOk(admin.get(), "SET pgsql-set_parser_algorithm=2")
        || !execOk(admin.get(), "SET pgsql-query_processor_parser=0")
        || !execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME")) {
        cleanup_and_bail(guard, "cannot configure the legacy parser and connection timeout");
    }
    if (native_supported
        && (!execOk(admin.get(), "SET pgsql-use_native_backend_protocol='false'")
            || !execOk(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"))) {
        cleanup_and_bail(guard, "cannot select the libpq backend protocol");
    }

    // Start from an empty pool so the poisoned connection is the only one in
    // it: anything left over would serve the pickup instead.
    const bool flushed = flushPool(admin.get(), guard);
    ok(flushed, "hostgroup %d starts with no pooled connection (ConnFree=%d)",
       BACKEND_HG, poolFree(admin.get(), BACKEND_HG));
    if (!flushed)
        cleanup_and_bail(guard, "cannot flush the backend pool");

    // ---- session A: poison exactly one pooled connection -------------------
    {
        auto a = openClient();
        if (!a || PQstatus(a.get()) != CONNECTION_OK)
            cleanup_and_bail(guard, "session A: client connection failed");
        const bool poisoned =
            execOk(a.get(), "SET bytea_output = 'escape'")
            && execOk(a.get(),
                  "DO $$ BEGIN EXECUTE format('CREATE TEMP TABLE stale_deadline_t_pad_%s AS SELECT 1', 1); END $$")
            && execOk(a.get(),
                  "SELECT set_config('statement_timeout', '"
                  + std::to_string(RESET_STATEMENT_TIMEOUT_MS) + "', false)");
        if (!poisoned)
            cleanup_and_bail(guard, "session A: could not poison the connection");
        // The disconnect returns the connection to the pool still carrying the
        // variable, the temp table and the timeout.
    }
    const int poisoned_pooled = poolFreeWithin(admin.get(), BACKEND_HG, 1, 10);
    ok(poisoned_pooled == 1,
       "session A left exactly one poisoned connection in the pool (ConnFree=%d)", poisoned_pooled);
    if (poisoned_pooled != 1)
        cleanup_and_bail(guard, "the poisoned connection was not pooled; the scenario cannot proceed");

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
        cleanup_and_bail(guard, "cannot take the pg_depend share lock");
    }

    // ---- session B, query 1: the pickup and the blocked reset ----------------
    // The reset runs ON this session; its DISCARD ALL blocks on the helper's
    // lock and is cancelled by the statement timeout session A armed. The
    // client seeing that 57014 IS the leak branch: the alternative branch
    // (backend connection unusable) retries on a fresh connection and the
    // client would see a result instead of the cancellation.
    auto b = openClient();
    if (!b || PQstatus(b.get()) != CONNECTION_OK)
        cleanup_and_bail(guard, "session B: client connection failed");
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

    const bool cleaned = guard.restore();
    if (!cleaned) diag("final cleanup failed; snapshots retained for retry");
    ok(cleaned, "runtime and memory state restored after the test");
    return exit_status();
}
