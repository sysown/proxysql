/**
 * @file pgsql-discard_all_txn_block-t.cpp
 * @brief DISCARD ALL, in and out of a transaction block, against a direct PostgreSQL oracle.
 *
 * WHY THIS EXISTS
 * ---------------
 * ProxySQL does not forward DISCARD ALL. It handles the command itself by resetting
 * its own per-session bookkeeping and fabricating the replies, so every rule
 * PostgreSQL applies to the command has to be reimplemented here -- and the one that
 * matters is that DISCARD ALL cannot run inside a transaction block.
 *
 * A batch of pipelined extended-query messages is a transaction block even without a
 * BEGIN: PostgreSQL opens an implicit one and commits it at Sync. Resetting the
 * session in the middle of such a batch drops the backend connection, which rolls the
 * batch back -- after the client has already been told the earlier statements
 * succeeded. That is silent data loss, and it is invisible to libpq's result API:
 * PQresultStatus() reports PGRES_COMMAND_OK either way.
 *
 * So this test compares the CLIENT-VISIBLE backend message stream, byte for byte,
 * against the same script run straight at PostgreSQL. The oracle is the real server,
 * which means every expectation here is the server's, not this file's -- including
 * the exact SQLSTATE (25001), the exact message text, whether a NoData answers a
 * portal Describe, and which transaction-state byte each ReadyForQuery carries.
 *
 * Both backend protocols are exercised, and that is not redundant: the first version of
 * this guard asked the backend connection whether a pipeline was open, which in libpq
 * mode is true for the whole extended-query frame whether or not anything was ever sent.
 * It passed in native mode and refused every extended DISCARD ALL in libpq mode. The
 * backend pool is flushed between the two phases -- pooled connections never change
 * protocol, so without the flush the second phase silently re-runs the first.
 *
 * KNOWN DIVERGENCE (asserted as such, not hidden)
 * ----------------------------------------------
 * PostgreSQL opens the implicit block only once the batch has actually run a statement,
 * so DISCARD ALL as the FIRST statement of a batch succeeds there even with more
 * statements pipelined behind it. ProxySQL refuses that with 0A000: handling the command
 * means replacing the session state the queued messages would then be processed against.
 * The oracle leg records what PostgreSQL really does; the assertion is that ProxySQL
 * refuses cleanly and leaves the client usable, not that it matches.
 *
 * INFRA: legacy-g4. Runtime state restored in memory only -- never SAVE ... TO DISK.
 */
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "pg_lite_client.h"  // MUST precede utils.h: mysql.h defines a PROTOCOL_VERSION macro
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

static const int PG_TIMEOUT_MS = 15000;
static const int BACKEND_HG = 0;
static const std::string FIXTURE = "discard_all_txn_block_fixture";

// ------------------------------------------------------------------ admin

static PGConnPtr createAdminConn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
       << " user=" << cl.admin_username << " password=" << cl.admin_password
       << " sslmode=disable";
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

// RAII: force frontend cleartext so pg_lite_client can drive the proxy leg.
// BAIL_OUT() is exit(255) and skips destructors, so every exit path after
// construction must call restore() explicitly. restore() is idempotent.
struct AuthMethodScope {
    PGconn* admin;
    std::string saved;
    bool ok = false, restored = false;
    explicit AuthMethodScope(PGconn* a) : admin(a) {
        saved = adminScalar(admin,
            "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-authentication_method'");
        if (saved.empty()) { diag("cannot read pgsql-authentication_method"); return; }
        ok = execAdmin(admin, "SET pgsql-authentication_method=1") &&
             execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    }
    void restore() {
        if (restored) return;
        restored = true;
        if (saved.empty()) return;
        execAdmin(admin, "SET pgsql-authentication_method=" + saved);
        execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
    }
    ~AuthMethodScope() { restore(); }
    AuthMethodScope(const AuthMethodScope&) = delete;
    AuthMethodScope& operator=(const AuthMethodScope&) = delete;
};

// Re-inserting the server rows drops every pooled backend connection with them.
// Needed between protocol phases: a pooled connection keeps the protocol it was
// opened with, so reusing one makes the second phase repeat the first.
struct ServerRow { std::string hostname, port, max_connections, comment; };

static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
    std::vector<ServerRow> rows;
    std::stringstream q;
    q << "SELECT hostname, port, max_connections, comment FROM pgsql_servers WHERE hostgroup_id=" << hg;
    PGresult* res = PQexec(admin, q.str().c_str());
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        for (int i = 0; i < PQntuples(res); i++) {
            ServerRow r;
            r.hostname = PQgetvalue(res, i, 0);
            r.port = PQgetvalue(res, i, 1);
            r.max_connections = PQgetvalue(res, i, 2);
            r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
            rows.push_back(std::move(r));
        }
    } else {
        diag("readServers failed: %s", PQerrorMessage(admin));
    }
    PQclear(res);
    return rows;
}

static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
    if (saved.empty()) return false;
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << hg;
    if (!execAdmin(admin, del.str())) return false;
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    for (const auto& r : saved) {
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) VALUES ("
            << hg << ",'" << r.hostname << "'," << r.port << ","
            << (r.max_connections.empty() ? std::string("1000") : r.max_connections)
            << ",'" << r.comment << "')";
        if (!execAdmin(admin, ins.str())) return false;
    }
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(200000);
    return true;
}

// ------------------------------------------------------- raw-wire legs

static std::unique_ptr<PgConnection> connectBackend() {
    auto c = std::make_unique<PgConnection>(PG_TIMEOUT_MS);
    c->connect(cl.pgsql_server_host, cl.pgsql_server_port, "postgres",
               cl.pgsql_root_username, cl.pgsql_root_password);
    return c;
}

static std::unique_ptr<PgConnection> connectProxy() {
    auto c = std::make_unique<PgConnection>(PG_TIMEOUT_MS);
    c->connect(cl.pgsql_host, cl.pgsql_port, "postgres",
               cl.pgsql_root_username, cl.pgsql_root_password);
    return c;
}

// A plain libpq connection straight to the backend, for checking what actually
// landed in the table. Deliberately not through the proxy: the question is what
// PostgreSQL kept, not what ProxySQL says it kept.
static PGConnPtr backendLibpq() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_server_host << " port=" << cl.pgsql_server_port
       << " user=" << cl.pgsql_root_username << " password=" << cl.pgsql_root_password
       << " dbname=postgres sslmode=disable";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

// --------------------------------------------------- capture + compare

static std::string hex(const std::vector<uint8_t>& b, size_t max = 96) {
    static const char* H = "0123456789abcdef";
    std::string s;
    const size_t n = b.size() < max ? b.size() : max;
    for (size_t i = 0; i < n; i++) { s.push_back(H[b[i] >> 4]); s.push_back(H[b[i] & 0xf]); }
    if (b.size() > max) s += "..";
    return s;
}

// Reduce ErrorResponse/NoticeResponse to Severity + SQLSTATE + Message. The dropped
// fields carry PostgreSQL source file names and line numbers, which are not part of
// the contract a client sees.
static std::vector<uint8_t> reduceErrorFields(const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    size_t i = 0;
    while (i < payload.size() && payload[i] != 0) {
        const char ftype = (char)payload[i];
        size_t vstart = i + 1, j = vstart;
        while (j < payload.size() && payload[j] != 0) j++;
        if (ftype == 'S' || ftype == 'C' || ftype == 'M') {
            out.push_back((uint8_t)ftype);
            out.insert(out.end(), payload.begin() + vstart, payload.begin() + j);
            out.push_back(0);
        }
        i = (j < payload.size()) ? j + 1 : j;
    }
    out.push_back(0);
    return out;
}

struct Msg { char type; std::vector<uint8_t> payload; };

// Read backend messages until `n_ready` ReadyForQuery('Z') messages have arrived.
static std::vector<Msg> collect(PgConnection& c, int n_ready) {
    std::vector<Msg> msgs;
    char type;
    std::vector<uint8_t> buf;
    int seen = 0;
    while (seen < n_ready) {
        c.readMessage(type, buf);
        Msg m;
        m.type = type;
        m.payload = (type == 'E' || type == 'N') ? reduceErrorFields(buf) : buf;
        msgs.push_back(std::move(m));
        if (type == 'Z') seen++;
    }
    return msgs;
}

static bool sameStream(const std::vector<Msg>& a, const std::vector<Msg>& b, std::string& why) {
    const size_t n = a.size() < b.size() ? a.size() : b.size();
    for (size_t i = 0; i < n; i++) {
        if (a[i].type != b[i].type) {
            char buf[200];
            snprintf(buf, sizeof(buf), "msg %zu: type oracle='%c' proxy='%c'", i, a[i].type, b[i].type);
            why = buf;
            return false;
        }
        if (a[i].payload != b[i].payload) {
            std::stringstream ss;
            ss << "msg " << i << " ('" << a[i].type << "') payload differs: oracle["
               << a[i].payload.size() << "B]=" << hex(a[i].payload)
               << " proxy[" << b[i].payload.size() << "B]=" << hex(b[i].payload);
            why = ss.str();
            return false;
        }
    }
    if (a.size() != b.size()) {
        std::stringstream ss;
        ss << "message count: oracle=" << a.size() << " proxy=" << b.size();
        why = ss.str();
        return false;
    }
    return true;
}

static std::string streamSummary(const std::vector<Msg>& m) {
    std::string s;
    for (const auto& x : m) s.push_back(x.type);
    return s;
}

// Every SQLSTATE carried by an ErrorResponse in the stream, comma separated.
static std::string errorCodes(const std::vector<Msg>& msgs) {
    std::string out;
    for (const auto& m : msgs) {
        if (m.type != 'E') continue;
        size_t i = 0;
        while (i < m.payload.size() && m.payload[i] != 0) {
            const char f = (char)m.payload[i];
            size_t vs = i + 1, j = vs;
            while (j < m.payload.size() && m.payload[j] != 0) j++;
            if (f == 'C') {
                if (!out.empty()) out += ",";
                out.append((const char*)&m.payload[vs], j - vs);
            }
            i = (j < m.payload.size()) ? j + 1 : j;
        }
    }
    return out;
}

// The transaction-state byte of the last ReadyForQuery in the stream.
static char lastReadyState(const std::vector<Msg>& msgs) {
    for (auto it = msgs.rbegin(); it != msgs.rend(); ++it)
        if (it->type == 'Z' && !it->payload.empty()) return (char)it->payload[0];
    return '?';
}

// ------------------------------------------------------------- scripts

// A full Parse -> Bind -> [Describe portal] -> Execute cycle, no Sync.
// pg_lite_client's executeParams() never sends the Parse, so every extended cycle
// here is driven message by message.
static void extStep(PgConnection& c, const std::string& name, const std::string& query,
                    bool describe_portal) {
    c.prepareStatement(name, query, false);
    c.bindStatement(name, "", {}, {}, false);
    if (describe_portal) c.describePortal("", false);
    c.executePortal("", 0, false);
}

// DISCARD ALL alone in its batch: the one shape ProxySQL is allowed to handle itself.
static void sc_lone_extended(PgConnection& c) {
    extStep(c, "da_lone", "DISCARD ALL", true);
    c.sendSync();
}

static void sc_lone_simple(PgConnection& c) {
    c.execute("DISCARD ALL");
}

// Explicit transaction, simple query. PostgreSQL refuses and leaves the transaction
// aborted, so the ROLLBACK afterwards is the client doing the only thing it can.
static void sc_txn_simple(PgConnection& c) {
    c.execute("BEGIN");
    c.execute("DISCARD ALL");
    c.execute("ROLLBACK");
}

static void sc_txn_extended(PgConnection& c) {
    c.execute("BEGIN");
    extStep(c, "da_txn", "DISCARD ALL", true);
    c.sendSync();
    c.execute("ROLLBACK");
}

// No BEGIN, but the batch itself is an implicit transaction block, so PostgreSQL
// refuses the DISCARD ALL just the same.
static void sc_implicit_batch(PgConnection& c) {
    extStep(c, "ib_sel", "SELECT 1", false);
    extStep(c, "ib_da", "DISCARD ALL", true);
    c.sendSync();
}

// DISCARD ALL first, another statement pipelined behind it. PostgreSQL accepts it;
// ProxySQL refuses it (see KNOWN DIVERGENCE in the file header).
static void sc_queued_behind(PgConnection& c) {
    extStep(c, "qb_da", "DISCARD ALL", false);
    extStep(c, "qb_sel", "SELECT 1", false);
    c.sendSync();
}

// A reported GUC is changed, then DISCARD ALL puts it back -- in a LATER batch, the way
// an application actually does it. PostgreSQL announces the revert with a ParameterStatus
// message; a client that caches DateStyle keeps formatting dates the old way without it.
static void sc_param_then_discard(PgConnection& c) {
    extStep(c, "ps_set", "SET DateStyle = 'Postgres, DMY'", true);
    c.sendSync();
    extStep(c, "ps_da", "DISCARD ALL", true);
    c.sendSync();
}

// Same thing with the SET sent as a simple query, which isolates DISCARD ALL's own
// reporting from the separate ordering bug the extended-protocol SET has.
static void sc_param_simple_then_discard(PgConnection& c) {
    c.execute("SET DateStyle = 'Postgres, DMY'");
    extStep(c, "pss_da", "DISCARD ALL", true);
    c.sendSync();
}

// A statement ran in an EARLIER batch, not this one. The implicit transaction block it
// opened ended at that batch's own Sync, so DISCARD ALL in the next batch must still be
// allowed. Every other case here uses a fresh connection, which is exactly why this one
// has to exist: it is the only one that catches per-batch state outliving its batch.
static void sc_prior_batch_then_discard(PgConnection& c) {
    extStep(c, "pb_sel", "SELECT 1", false);
    c.sendSync();
    extStep(c, "pb_da", "DISCARD ALL", true);
    c.sendSync();
}

// ---- #6417: the transaction keyword tracker drifting from the backend ----------
//
// ProxySQL's keyword tracker reads only the first word of each query. `BEGIN; SELECT 1;
// COMMIT` sent as ONE query is recorded as a BEGIN that never ends, although the backend
// reports idle ('I') when it is done. The tracker is dropped when the backend goes back to
// the pool, so these scripts first pin the backend to the session (temp table, custom GUC,
// LISTEN, savepoint) to keep it -- and the stale BEGIN -- around for the DISCARD ALL.
// PostgreSQL runs that DISCARD ALL; ProxySQL used to refuse it with 25001, destroy the idle
// backend and poison the session.

static void sc_stale_temp(PgConnection& c) {
    c.execute("CREATE TEMP TABLE da_tt(i int)");
    c.execute("BEGIN; SELECT 1; COMMIT");
    c.execute("DISCARD ALL");
}

static void sc_stale_temp_extended(PgConnection& c) {
    c.execute("CREATE TEMP TABLE da_tt(i int)");
    c.execute("BEGIN; SELECT 1; COMMIT");
    extStep(c, "st_da", "DISCARD ALL", true);
    c.sendSync();
}

// The row-level-security shape. A custom GUC locks the session on its hostgroup, and
// the tracker is not fed while locked, so this one never drifted; it guards the lock.
static void sc_stale_guc(PgConnection& c) {
    c.execute("SET app.da_tenant = '1'");
    c.execute("BEGIN; SELECT 1; COMMIT");
    c.execute("DISCARD ALL");
}

static void sc_stale_listen(PgConnection& c) {
    c.execute("LISTEN da_ch");
    c.execute("BEGIN; SELECT 1; COMMIT");
    c.execute("DISCARD ALL");
}

// No external pin: the stale savepoint count is what keeps the backend attached.
static void sc_stale_savepoint(PgConnection& c) {
    c.execute("BEGIN");
    c.execute("SAVEPOINT s; SELECT 1; RELEASE s; COMMIT");
    c.execute("DISCARD ALL");
}

// A failed statement never reaches the tracker. The deferred check fails the COMMIT,
// which still ends the transaction: the backend reports 'I' with the tracker at BEGIN.
static void sc_stale_failed_commit(PgConnection& c) {
    c.execute("CREATE TEMP TABLE da_p(i int primary key)");
    c.execute("CREATE TEMP TABLE da_c(i int references da_p deferrable initially deferred)");
    c.execute("BEGIN");
    c.execute("INSERT INTO da_c VALUES (1)");
    c.execute("COMMIT");
    c.execute("DISCARD ALL");
}

// The other direction: a transaction the tracker never saw open. PostgreSQL refuses the
// DISCARD ALL and leaves the transaction aborted; ProxySQL used to run it, silently
// rolling the transaction back and leaving the client in autocommit.
static void sc_hidden_txn(PgConnection& c) {
    c.execute("SELECT 1; BEGIN");
    c.execute("DISCARD ALL");
    c.execute("ROLLBACK");
}

static void sc_hidden_txn_chain(PgConnection& c) {
    c.execute("BEGIN");
    c.execute("COMMIT AND CHAIN");
    c.execute("DISCARD ALL");
    c.execute("ROLLBACK");
}

// Same, ended the way an extended-protocol-only driver (pgjdbc, Npgsql) has to.
static void sc_hidden_txn_ext_rollback(PgConnection& c) {
    c.execute("SELECT 1; BEGIN");
    c.execute("DISCARD ALL");
    extStep(c, "ht_rb", "ROLLBACK", false);
    c.sendSync();
}

// ---- #6417: the decision mid-batch -------------------------------------------
//
// Once a statement of the batch has run, the backend's last ReadyForQuery predates the
// batch and only the keyword tracker followed it. These cover the tracker deciding there.

// The stale BEGIN of the temp-table case, but with DISCARD ALL after a statement in the
// same batch: the batch's implicit block, refused as such ('I'), never as an explicit
// transaction that poisons the session.
static void sc_stale_temp_batch(PgConnection& c) {
    c.execute("CREATE TEMP TABLE da_tt(i int)");
    c.execute("BEGIN; SELECT 1; COMMIT");
    extStep(c, "sb_sel", "SELECT 1", false);
    extStep(c, "sb_da", "DISCARD ALL", true);
    c.sendSync();
}

// A BEGIN run earlier in the same batch makes it an explicit transaction.
static void sc_begin_same_batch(PgConnection& c) {
    extStep(c, "bs_begin", "BEGIN", false);
    extStep(c, "bs_da", "DISCARD ALL", true);
    c.sendSync();
    c.execute("ROLLBACK");
}

// A transaction the tracker never saw, carried into a batch: the tracker must start the
// batch knowing about it, since mid-batch nothing else is asked.
static void sc_hidden_txn_batch(PgConnection& c) {
    c.execute("SELECT 1; BEGIN");
    extStep(c, "hb_sel", "SELECT 1", false);
    extStep(c, "hb_da", "DISCARD ALL", true);
    c.sendSync();
    c.execute("ROLLBACK");
}

// The same, with the unseen transaction left by an extended-protocol batch: the tracker
// has to be brought in line at that batch's Sync, not only after a simple query.
static void sc_hidden_chain_batch(PgConnection& c) {
    extStep(c, "hc_begin", "BEGIN", false);
    c.sendSync();
    extStep(c, "hc_chain", "COMMIT AND CHAIN", false);
    c.sendSync();
    extStep(c, "hc_sel", "SELECT 1", false);
    extStep(c, "hc_da", "DISCARD ALL", true);
    c.sendSync();
    c.execute("ROLLBACK");
}

// `todo` marks a case that fails for a reason outside this fix's scope. The assertion is
// wrapped in todo_start()/todo_end(), so a `not ok` does not fail the run but the
// divergence stays in the TAP output every time -- recorded rather than deleted. The
// tap library's message buffer is 128 bytes, so keep these short. `native_only` skips a
// script ProxySQL refuses on the libpq backend protocol by design (LISTEN).
struct Case { const char* name; void (*fn)(PgConnection&); int n_ready; const char* todo; bool native_only; };

static const Case PARITY_CASES[] = {
    { "lone DISCARD ALL, extended protocol",      sc_lone_extended,  1, nullptr },
    { "lone DISCARD ALL, simple query",           sc_lone_simple,    1, nullptr },
    { "DISCARD ALL in an explicit transaction",   sc_txn_simple,     3, nullptr },
    { "DISCARD ALL in an explicit transaction, extended protocol", sc_txn_extended, 3, nullptr },
    { "DISCARD ALL after a statement in the same batch", sc_implicit_batch, 1, nullptr },
    { "DISCARD ALL after a statement in an EARLIER batch", sc_prior_batch_then_discard, 2, nullptr },
    { "SET a reported GUC by simple query, then DISCARD ALL", sc_param_simple_then_discard, 2, nullptr },
    // The failure here is in the SET, not the DISCARD ALL: ProxySQL injects the
    // ParameterStatus before forwarding the SET, so it arrives ahead of the backend's
    // NoData and CommandComplete instead of after them. Pre-existing, and the DISCARD
    // half of this script is already covered by the simple-query case above.
    { "SET a reported GUC by extended protocol, then DISCARD ALL", sc_param_then_discard, 2,
      "extended-protocol SET sends ParameterStatus before CommandComplete, not after "
      "(pre-existing, unrelated to DISCARD ALL)" },
    { "#6417 stale BEGIN, temp table pin, DISCARD ALL",          sc_stale_temp,          3, nullptr },
    { "#6417 stale BEGIN, temp table pin, extended DISCARD ALL", sc_stale_temp_extended, 3, nullptr },
    { "#6417 stale BEGIN, custom GUC pin, DISCARD ALL",          sc_stale_guc,           3, nullptr },
    { "#6417 stale BEGIN, LISTEN pin, DISCARD ALL",              sc_stale_listen,        3, nullptr, true },
    { "#6417 stale savepoint, DISCARD ALL",                      sc_stale_savepoint,     3, nullptr },
    { "#6417 stale BEGIN after a failed COMMIT, DISCARD ALL",    sc_stale_failed_commit, 6, nullptr },
    { "#6417 BEGIN unseen by tracker (SELECT 1; BEGIN)",         sc_hidden_txn,          3, nullptr },
    { "#6417 BEGIN unseen by tracker (COMMIT AND CHAIN)",        sc_hidden_txn_chain,    4, nullptr },
    { "#6417 BEGIN unseen by tracker, extended ROLLBACK",        sc_hidden_txn_ext_rollback, 3, nullptr },
    { "#6417 stale BEGIN, temp table pin, DISCARD ALL mid-batch", sc_stale_temp_batch,   3, nullptr },
    { "#6417 BEGIN and DISCARD ALL in the same batch",           sc_begin_same_batch,    2, nullptr },
    { "#6417 BEGIN unseen by tracker, DISCARD ALL mid-batch",    sc_hidden_txn_batch,    3, nullptr },
    { "#6417 extended COMMIT AND CHAIN, DISCARD ALL mid-batch",  sc_hidden_chain_batch,  4, nullptr },
};

// --------------------------------------------------------- run one leg

// Runs `fn` on a fresh connection and returns the message stream, or an empty
// vector plus a reason if the connection or the script blew up.
static std::vector<Msg> runLeg(bool via_proxy, void (*fn)(PgConnection&), int n_ready,
                               std::string& err) {
    try {
        auto c = via_proxy ? connectProxy() : connectBackend();
        fn(*c);
        return collect(*c, n_ready);
    } catch (const std::exception& e) {
        err = e.what();
    } catch (...) {
        err = "unknown exception";
    }
    return {};
}

// ------------------------------------------------------------ durability

static long long fixtureRowCount(PGconn* be) {
    const std::string q = "SELECT count(*) FROM " + FIXTURE;
    PGresult* r = PQexec(be, q.c_str());
    long long n = -1;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) n = atoll(PQgetvalue(r, 0, 0));
    PQclear(r);
    return n;
}

static bool truncateFixture(PGconn* be) {
    const std::string q = "TRUNCATE " + FIXTURE;
    PGresult* r = PQexec(be, q.c_str());
    bool good = (PQresultStatus(r) == PGRES_COMMAND_OK);
    PQclear(r);
    return good;
}

// INSERT and DISCARD ALL sharing one Sync. PostgreSQL refuses the DISCARD ALL and
// rolls the INSERT back with the implicit transaction. Whatever ProxySQL replies,
// the row must not end up in a different place than it does on a direct connection
// -- a proxy that reports success and drops the row is silent data loss.
static void sc_durability(PgConnection& c) {
    extStep(c, "du_ins", "INSERT INTO " + FIXTURE + " VALUES (1)", false);
    extStep(c, "du_da", "DISCARD ALL", true);
    c.sendSync();
}

// #6249: reporting ReadyForQuery(E) is not enough. The next statement must
// remain rejected even though the local DISCARD handler destroyed the backend.
static void checkAbortedRecovery(bool extended_discard, const char* recovery, const char* mode) {
    bool rejected_discard = false, stayed_aborted = false, recovered = false;
    bool no_committed_write = false, usable = false;
    try {
        PGConnPtr be = backendLibpq();
        if (!be || PQstatus(be.get()) != CONNECTION_OK || !truncateFixture(be.get()))
            throw std::runtime_error("cannot initialize durability fixture");
        auto c = connectProxy();
        c->execute("BEGIN");
        const auto begin = collect(*c, 1);
        c->execute("INSERT INTO " + FIXTURE + " VALUES (1)");
        const auto before_discard = collect(*c, 1);
        if (!errorCodes(before_discard).empty() || lastReadyState(before_discard) != 'T')
            throw std::runtime_error("cannot insert within the transaction before DISCARD");
        if (extended_discard) {
            extStep(*c, "abort_discard", "DISCARD ALL", true);
            c->sendSync();
        } else {
            c->execute("DISCARD ALL");
        }
        const auto discard = collect(*c, 1);
        rejected_discard = lastReadyState(begin) == 'T' &&
            errorCodes(discard) == "25001" && lastReadyState(discard) == 'E';

        c->execute("SELECT 1");
        const auto select = collect(*c, 1);
        c->execute("INSERT INTO " + FIXTURE + " VALUES (6249)");
        const auto insert = collect(*c, 1);
        extStep(*c, "abort_write", "INSERT INTO " + FIXTURE + " VALUES (6249)", false);
        c->sendSync();
        const auto extended_insert = collect(*c, 1);
        stayed_aborted = errorCodes(select) == "25P02" && lastReadyState(select) == 'E' &&
            errorCodes(insert) == "25P02" && lastReadyState(insert) == 'E' &&
            errorCodes(extended_insert) == "25P02" && lastReadyState(extended_insert) == 'E';
        diag("  after rejected DISCARD: SELECT=%s INSERT=%s extended INSERT=%s",
             errorCodes(select).c_str(), errorCodes(insert).c_str(), errorCodes(extended_insert).c_str());

        c->execute(recovery);
        const auto end = collect(*c, 1);
        const std::vector<uint8_t> rollback_tag = {'R','O','L','L','B','A','C','K',0};
        bool rolled_back = false;
        for (const auto& m : end) if (m.type == 'C' && m.payload == rollback_tag) rolled_back = true;
        recovered = errorCodes(end).empty() && lastReadyState(end) == 'I' && rolled_back;
        no_committed_write = fixtureRowCount(be.get()) == 0;

        c->execute("BEGIN");
        const auto next_begin = collect(*c, 1);
        c->execute("INSERT INTO " + FIXTURE + " VALUES (1)");
        const auto next_insert = collect(*c, 1);
        c->execute("ROLLBACK");
        const auto next_rollback = collect(*c, 1);
        c->execute("DISCARD ALL");
        const auto next_discard = collect(*c, 1);
        usable = errorCodes(next_begin).empty() && lastReadyState(next_begin) == 'T' &&
            errorCodes(next_insert).empty() && lastReadyState(next_insert) == 'T' &&
            errorCodes(next_rollback).empty() && lastReadyState(next_rollback) == 'I' &&
            errorCodes(next_discard).empty() && lastReadyState(next_discard) == 'I' &&
            fixtureRowCount(be.get()) == 0;
    } catch (const std::exception& e) {
        diag("aborted transaction recovery probe failed: %s", e.what());
    }
    const char* wire = extended_discard ? "extended" : "simple";
    ok(rejected_discard, "DISCARD abort [%s/%s/%s]: reports 25001 and aborted state", mode, wire, recovery);
    ok(stayed_aborted, "DISCARD abort [%s/%s/%s]: subsequent simple/extended statements rejected with 25P02", mode, wire, recovery);
    ok(recovered, "DISCARD abort [%s/%s/%s]: recovery reports ROLLBACK and idle state", mode, wire, recovery);
    ok(no_committed_write, "DISCARD abort [%s/%s/%s]: rejected writes never commit", mode, wire, recovery);
    ok(usable, "DISCARD abort [%s/%s/%s]: new transaction and idle DISCARD work after recovery", mode, wire, recovery);
}

// ------------------------------------------------- #6417 non-parity checks

static long long txPoisonedTotal(PGconn* admin) {
    const std::string v = adminScalar(admin,
        "SELECT Variable_Value FROM stats_pgsql_global WHERE Variable_Name='pgsql_tx_poisoned_total'");
    return v.empty() ? -1 : atoll(v.c_str());
}

static bool hasCommandTag(const std::vector<Msg>& msgs, const char* tag) {
    const size_t n = strlen(tag) + 1;
    for (const auto& m : msgs)
        if (m.type == 'C' && m.payload.size() == n && memcmp(m.payload.data(), tag, n) == 0) return true;
    return false;
}

// Scripts whose stream cannot be compared byte for byte with PostgreSQL: a local ROLLBACK
// carries no "no transaction in progress" warning, and a multi-statement SET emits
// ParameterStatus messages of its own. What must hold is that the stale tracker no longer
// matters: DISCARD ALL succeeds on the idle backend, the session stays usable and nothing
// is poisoned.
static void checkStaleTracker(PGconn* admin, const char* name, const std::vector<const char*>& setup,
                              bool extended_discard, const char* mode) {
    bool discarded = false, usable = false, not_poisoned = false;
    std::string detail;
    try {
        const long long poisoned_before = txPoisonedTotal(admin);
        auto c = connectProxy();
        for (const char* q : setup) {
            c->execute(q);
            const auto r = collect(*c, 1);
            if (!errorCodes(r).empty()) throw std::runtime_error(std::string("setup failed: ") + q);
        }
        if (extended_discard) {
            extStep(*c, "stale_da", "DISCARD ALL", true);
            c->sendSync();
        } else {
            c->execute("DISCARD ALL");
        }
        const auto discard = collect(*c, 1);
        discarded = errorCodes(discard).empty() && lastReadyState(discard) == 'I' &&
            hasCommandTag(discard, "DISCARD ALL");
        c->execute("SELECT 1");
        const auto select = collect(*c, 1);
        usable = errorCodes(select).empty() && lastReadyState(select) == 'I';
        not_poisoned = poisoned_before >= 0 && txPoisonedTotal(admin) == poisoned_before;
        detail = "DISCARD: " + streamSummary(discard) + " (SQLSTATE '" + errorCodes(discard) +
            "'), SELECT: " + streamSummary(select) + " (SQLSTATE '" + errorCodes(select) + "')";
    } catch (const std::exception& e) {
        detail = e.what();
    }
    if (!(discarded && usable && not_poisoned)) diag("  %s", detail.c_str());
    ok(discarded && usable && not_poisoned,
       "%s [%s]: DISCARD ALL succeeds, session usable, not poisoned", name, mode);
}

static const int STALE_CHECKS = 3;

// ---- #6417: a transaction ended earlier in the same batch ----------------------
//
// [BEGIN, Sync] leaves the backend at 'T'. In the next batch, [COMMIT, DISCARD ALL,
// Sync], the COMMIT runs and ends that transaction, but the 'T' is still the last
// ReadyForQuery when DISCARD ALL is reached. Taking it for an explicit transaction
// destroyed the idle backend, poisoned the session and answered 'E'.
//
// The streams cannot be compared with PostgreSQL's: it finishes a transaction-control
// statement at once, so the DISCARD ALL after it is in no block and runs, while ProxySQL
// refuses a DISCARD ALL that is not the first statement of its batch (the same rule as
// KNOWN DIVERGENCE in the file header). What must hold is that the refusal is the
// pipelined one -- client left idle and usable, nothing poisoned -- and that the
// transaction ended exactly as it does on a direct connection.
//
// With `lock_first`, a custom GUC first locks the session on its hostgroup. The tracker
// is not fed while locked, so it never sees the COMMIT or ROLLBACK run mid-batch; it must
// therefore not be opened from the backend's 'T' at the end of [BEGIN, Sync] either, or
// the DISCARD ALL is refused as explicit (25001, 'E', poisoned) where v3.0.11 gave the
// pipelined refusal with 'I'.
static std::vector<Msg> batchEndThenDiscard(PgConnection& c, const char* end_cmd, bool lock_first) {
    if (lock_first) {
        c.execute("SET app.da_lock = '1'");
        const auto lock = collect(c, 1);
        if (!errorCodes(lock).empty() || lastReadyState(lock) != 'I')
            throw std::runtime_error("cannot lock the session on its hostgroup");
    }
    extStep(c, "be_begin", "BEGIN", false);
    c.sendSync();
    const auto begin = collect(c, 1);
    extStep(c, "be_ins", "INSERT INTO " + FIXTURE + " VALUES (6417)", false);
    c.sendSync();
    const auto insert = collect(c, 1);
    if (!errorCodes(begin).empty() || lastReadyState(begin) != 'T' ||
        !errorCodes(insert).empty() || lastReadyState(insert) != 'T')
        throw std::runtime_error("cannot open the transaction before the batch");
    extStep(c, "be_end", end_cmd, false);
    extStep(c, "be_da", "DISCARD ALL", true);
    c.sendSync();
    return collect(c, 1);
}

static void checkBatchEndThenDiscard(PGconn* admin, const char* end_cmd, bool lock_first, const char* mode) {
    bool ended = false, idle = false, usable = false, not_poisoned = false, same_rows = false;
    std::string detail;
    try {
        PGConnPtr be = backendLibpq();
        if (!be || PQstatus(be.get()) != CONNECTION_OK || !truncateFixture(be.get()))
            throw std::runtime_error("cannot initialize durability fixture");
        std::vector<Msg> oracle;
        {
            auto c = connectBackend();
            oracle = batchEndThenDiscard(*c, end_cmd, lock_first);
        }
        const long long oracle_rows = fixtureRowCount(be.get());
        if (!truncateFixture(be.get())) throw std::runtime_error("cannot truncate durability fixture");

        const long long poisoned_before = txPoisonedTotal(admin);
        auto c = connectProxy();
        const auto proxy = batchEndThenDiscard(*c, end_cmd, lock_first);
        ended = hasCommandTag(proxy, end_cmd);
        idle = lastReadyState(proxy) == 'I';
        c->execute("SELECT 1");
        const auto select = collect(*c, 1);
        usable = errorCodes(select).empty() && lastReadyState(select) == 'I';
        not_poisoned = poisoned_before >= 0 && txPoisonedTotal(admin) == poisoned_before;
        const long long proxy_rows = fixtureRowCount(be.get());
        same_rows = oracle_rows >= 0 && oracle_rows == proxy_rows;
        detail = "direct PostgreSQL: " + streamSummary(oracle) + " (SQLSTATE '" + errorCodes(oracle) +
            "', rows " + std::to_string(oracle_rows) + "); via ProxySQL: " + streamSummary(proxy) +
            " (SQLSTATE '" + errorCodes(proxy) + "', last ReadyForQuery '" + lastReadyState(proxy) +
            "', rows " + std::to_string(proxy_rows) + "), next SELECT: " + streamSummary(select) +
            " (SQLSTATE '" + errorCodes(select) + "')";
    } catch (const std::exception& e) {
        detail = e.what();
    }
    diag("  %s", detail.c_str());
    ok(ended && idle && usable && not_poisoned && same_rows,
       "#6417 %s[BEGIN] then [%s, DISCARD ALL] [%s]: client idle and usable, not poisoned, same rows as PostgreSQL",
       lock_first ? "hostgroup-locked " : "", end_cmd, mode);
}

static const int BATCH_END_CHECKS = 4;

// ------------------------------------------------------------------ main

static const char* MODE_NAME[2] = { "libpq backend protocol", "native backend protocol" };

int main(int, char**) {
    // Existing parity cases plus 5 assertions for each DISCARD/recovery shape.
    plan((int)((sizeof(PARITY_CASES) / sizeof(PARITY_CASES[0]) + 2 + 5 * 2 * 2 + STALE_CHECKS +
                BATCH_END_CHECKS) * 2));

    if (cl.getEnv()) return exit_status();

    auto adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();
    const bool native_supported = pgsql_native_supported(admin);

    const std::string saved_native = adminScalar(admin,
        "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-use_native_backend_protocol'");
    const std::vector<ServerRow> saved_servers = readServers(admin, BACKEND_HG);

    AuthMethodScope auth(admin);
    auto cleanup = [&]() {
        if (!saved_native.empty())
            setNativeMode(admin, saved_native == "true" || saved_native == "1");
        flushBackendPool(admin, BACKEND_HG, saved_servers);
        auth.restore();
    };
    if (!auth.ok) { cleanup(); BAIL_OUT("failed to force frontend cleartext auth"); }
    if (saved_servers.empty()) { cleanup(); BAIL_OUT("no pgsql_servers rows for hostgroup %d", BACKEND_HG); }

    // ---- fixture table, on the backend, not through the proxy ---------------
    {
        PGConnPtr be = backendLibpq();
        if (!be || PQstatus(be.get()) != CONNECTION_OK) {
            cleanup();
            BAIL_OUT("cannot reach the backend directly to build the fixture");
        }
        PQclear(PQexec(be.get(), ("DROP TABLE IF EXISTS " + FIXTURE).c_str()));
        PGresult* r = PQexec(be.get(), ("CREATE TABLE " + FIXTURE + " (id int4)").c_str());
        const bool made = (PQresultStatus(r) == PGRES_COMMAND_OK);
        PQclear(r);
        if (!made) { cleanup(); BAIL_OUT("could not create the fixture table"); }
    }

    for (int mode = 0; mode < 2; mode++) {
        const bool native = (mode == 1);
        if (native && !native_supported) {
            skip((int)(sizeof(PARITY_CASES) / sizeof(PARITY_CASES[0]) + 2 + 5 * 2 * 2 + STALE_CHECKS +
                       BATCH_END_CHECKS),
                 "native backend protocol is unavailable in v3.0");
            continue;
        }
        diag("================ %s ================", MODE_NAME[mode]);
        if (native_supported && !setNativeMode(admin, native)) { cleanup(); BAIL_OUT("cannot set the backend protocol"); }
        // Pooled connections keep the protocol they were opened with, so without this
        // the second phase would quietly re-run the first.
        if (!flushBackendPool(admin, BACKEND_HG, saved_servers)) {
            cleanup();
            BAIL_OUT("cannot flush the backend pool between protocol phases");
        }

        for (bool extended : {false, true}) {
            for (const char* recovery : {"ROLLBACK", "COMMIT"})
                checkAbortedRecovery(extended, recovery, MODE_NAME[mode]);
        }

        // ---- parity cases: the proxy's bytes must be PostgreSQL's bytes ------
        for (const auto& kase : PARITY_CASES) {
            if (kase.native_only && !native) {
                skip(1, "%s: LISTEN needs the native backend protocol", kase.name);
                continue;
            }
            std::string oerr, perr;
            std::vector<Msg> oracle = runLeg(false, kase.fn, kase.n_ready, oerr);
            std::vector<Msg> proxy  = runLeg(true,  kase.fn, kase.n_ready, perr);
            if (!oerr.empty() || !perr.empty()) {
                if (kase.todo) todo_start("%s", kase.todo);
                ok(false, "%s [%s]: leg failed -- oracle:'%s' proxy:'%s'",
                   kase.name, MODE_NAME[mode], oerr.c_str(), perr.c_str());
                if (kase.todo) todo_end();
                continue;
            }
            std::string why;
            const bool same = sameStream(oracle, proxy, why);
            if (!same) {
                diag("  oracle stream: %s  (SQLSTATE %s, last ReadyForQuery '%c')",
                     streamSummary(oracle).c_str(), errorCodes(oracle).c_str(), lastReadyState(oracle));
                diag("  proxy  stream: %s  (SQLSTATE %s, last ReadyForQuery '%c')",
                     streamSummary(proxy).c_str(), errorCodes(proxy).c_str(), lastReadyState(proxy));
            }
            if (kase.todo) todo_start("%s", kase.todo);
            ok(same, "%s [%s]: identical to direct PostgreSQL%s%s",
               kase.name, MODE_NAME[mode], same ? "" : " -- ", same ? "" : why.c_str());
            if (kase.todo) todo_end();
        }

        // ---- queued-behind: both refuse, codes differ on purpose -------------
        {
            std::string oerr, perr;
            std::vector<Msg> oracle = runLeg(false, sc_queued_behind, 1, oerr);
            std::vector<Msg> proxy  = runLeg(true,  sc_queued_behind, 1, perr);
            if (!oerr.empty() || !perr.empty()) {
                ok(false, "DISCARD ALL with statements queued behind it [%s]: leg failed -- oracle:'%s' proxy:'%s'",
                   MODE_NAME[mode], oerr.c_str(), perr.c_str());
            } else {
                const std::string ocodes = errorCodes(oracle), pcodes = errorCodes(proxy);
                diag("  direct PostgreSQL: %s (SQLSTATE '%s'); via ProxySQL: %s (SQLSTATE '%s')",
                     streamSummary(oracle).c_str(), ocodes.c_str(),
                     streamSummary(proxy).c_str(), pcodes.c_str());
                // Documented divergence: PostgreSQL accepts this, ProxySQL refuses it.
                // What must hold is that the refusal is clean -- a real ErrorResponse
                // carrying the feature-not-supported code, and a client left in a state
                // it can keep using rather than waiting for a reply that never comes.
                const bool refused_cleanly = (pcodes == "0A000");
                const bool ready = (lastReadyState(proxy) == 'I');
                ok(refused_cleanly && ready,
                   "DISCARD ALL with statements queued behind it [%s]: refused cleanly, client left idle and usable",
                   MODE_NAME[mode]);
            }
        }

        // ---- #6417: stale tracker, streams not comparable with PostgreSQL ------
        checkStaleTracker(admin, "#6417 local ROLLBACK does not heal a stale BEGIN",
            { "CREATE TEMP TABLE da_tt(i int)", "BEGIN; SELECT 1; COMMIT", "ROLLBACK" },
            false, MODE_NAME[mode]);
        // The multi-statement SET locks the session on its hostgroup, and the tracker is
        // not fed while locked, so the COMMIT that ends the transaction is never seen.
        checkStaleTracker(admin, "#6417 COMMIT unseen under a hostgroup lock",
            { "BEGIN", "SET DateStyle='ISO'; SELECT 1", "COMMIT" },
            false, MODE_NAME[mode]);
        checkStaleTracker(admin, "#6417 COMMIT unseen under a hostgroup lock, extended DISCARD",
            { "BEGIN", "SET DateStyle='ISO'; SELECT 1", "COMMIT" },
            true, MODE_NAME[mode]);

        // ---- #6417: transaction ended earlier in the same batch ----------------
        for (bool lock_first : {false, true})
            for (const char* end_cmd : {"COMMIT", "ROLLBACK"})
                checkBatchEndThenDiscard(admin, end_cmd, lock_first, MODE_NAME[mode]);

        // ---- durability: the row must land in the same place on both legs ----
        {
            PGConnPtr be = backendLibpq();
            if (!be || PQstatus(be.get()) != CONNECTION_OK) {
                ok(false, "INSERT + DISCARD ALL in one batch [%s]: no direct backend connection",
                   MODE_NAME[mode]);
            } else {
                std::string oerr, perr;
                long long oracle_rows = -1, proxy_rows = -1;

                truncateFixture(be.get());
                runLeg(false, sc_durability, 1, oerr);
                oracle_rows = fixtureRowCount(be.get());

                truncateFixture(be.get());
                runLeg(true, sc_durability, 1, perr);
                proxy_rows = fixtureRowCount(be.get());

                diag("  rows left after INSERT + DISCARD ALL: direct PostgreSQL=%lld, via ProxySQL=%lld",
                     oracle_rows, proxy_rows);
                ok(oracle_rows >= 0 && oracle_rows == proxy_rows,
                   "INSERT + DISCARD ALL in one batch [%s]: same rows committed as direct PostgreSQL",
                   MODE_NAME[mode]);
            }
        }
    }

    // ---- teardown -----------------------------------------------------------
    {
        PGConnPtr be = backendLibpq();
        if (be && PQstatus(be.get()) == CONNECTION_OK)
            PQclear(PQexec(be.get(), ("DROP TABLE IF EXISTS " + FIXTURE).c_str()));
    }
    cleanup();
    return exit_status();
}
