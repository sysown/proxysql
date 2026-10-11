/**
 * @file pgsql-local_error_txn_state-t.cpp
 * @brief #6424: an error ProxySQL raises itself, inside a transaction, against a direct PostgreSQL oracle.
 *
 * WHY THIS EXISTS
 * ---------------
 * Some errors never reach the backend: ProxySQL answers them on its own. An Execute or a
 * portal Describe for a portal that does not exist, a query rule's error_msg, a
 * hostgroup-lock refusal, and more. PostgreSQL aborts the transaction block on ANY
 * error, so it follows such an error with ReadyForQuery('E') and rejects everything but
 * ROLLBACK/COMMIT until the client ends the transaction. ProxySQL always sent
 * ReadyForQuery('I') instead, while the client's transaction was still open on the
 * pinned backend. A driver that trusts the status byte then skips its ROLLBACK, and a
 * later COMMIT commits work that was supposed to be aborted.
 *
 * The parity cases compare the CLIENT-VISIBLE message stream, SQLSTATE and message text
 * included, against the same script run straight at PostgreSQL. The durability checks
 * assert what matters most and is invisible on the wire: after a local error inside a
 * transaction, COMMIT must not commit the work done before it.
 *
 * A transaction whose backend already reports 'E' (it saw an error of its own) needs
 * no help from ProxySQL: the backend handles the ROLLBACK, including one sent over the
 * extended protocol, and that case is in the parity set too.
 *
 * A backend still at 'T' never saw the error, so ProxySQL poisons the session and ends
 * the transaction itself when the client sends ROLLBACK/COMMIT. Extended-only drivers
 * (pgjdbc's rollback(), with the statement unnamed or, once server-prepared, named) send
 * it as Parse/Bind/Execute/Sync, and that must recover the session just like a simple
 * ROLLBACK: before, every Sync got 25P02 forever and the connection was lost to the
 * pool. Those shapes are in the parity set, and in the durability checks.
 *
 * An error_msg query rule that refuses a Parse in the middle of a frame must also throw
 * the rest of that frame away: nothing queued behind the error may run.
 *
 * Both backend protocols are exercised; the backend pool is flushed between the two
 * phases because pooled connections keep the protocol they were opened with. Named
 * portals exist only with the native backend protocol; with libpq they are refused with
 * 0A000, and only the transaction-state bytes are compared there.
 *
 * INFRA: legacy-g1. Runtime state restored in memory only -- never SAVE ... TO DISK.
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
static const int RULE_ID = 6424;
static const std::string FIXTURE = "local_error_txn_state_fixture";
// The statement the query rule refuses with error_msg. ProxySQL never forwards it.
static const std::string RULE_QUERY = "SELECT 'local_error_6424'";

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

static bool setRule(PGconn* admin, bool on) {
    std::stringstream del;
    del << "DELETE FROM pgsql_query_rules WHERE rule_id=" << RULE_ID;
    if (!execAdmin(admin, del.str())) return false;
    if (on) {
        std::stringstream ins;
        ins << "INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES ("
            << RULE_ID << ", 1, '^SELECT ''local_error_6424''', 'refused by rule " << RULE_ID << "', 1)";
        if (!execAdmin(admin, ins.str())) return false;
    }
    return execAdmin(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
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
// landed in the table. Deliberately not through the proxy.
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
// fields carry PostgreSQL source file names and line numbers.
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

// The transaction-state byte of every ReadyForQuery in the stream, in order.
static std::string readyStates(const std::vector<Msg>& msgs) {
    std::string s;
    for (const auto& m : msgs)
        if (m.type == 'Z' && !m.payload.empty()) s.push_back((char)m.payload[0]);
    return s;
}

static char lastReadyState(const std::vector<Msg>& msgs) {
    const std::string s = readyStates(msgs);
    return s.empty() ? '?' : s.back();
}

static bool hasCommandTag(const std::vector<Msg>& msgs, const std::string& tag) {
    std::vector<uint8_t> want(tag.begin(), tag.end());
    want.push_back(0);
    for (const auto& m : msgs) if (m.type == 'C' && m.payload == want) return true;
    return false;
}

// ------------------------------------------------------------- scripts

// Execute of the unnamed portal with no Bind before it: answered by ProxySQL itself
// with 34000, the backend never sees it.
static void sc_unnamed_execute_idle(PgConnection& c) {
    c.executePortal("", 0, true);
}

static void sc_unnamed_execute_txn(PgConnection& c) {
    c.execute("BEGIN");
    c.executePortal("", 0, true);
    c.execute("SELECT 1");
    c.execute("ROLLBACK");
}

static void sc_unnamed_describe_txn(PgConnection& c) {
    c.execute("BEGIN");
    c.describePortal("", true);
    c.execute("SELECT 1");
    c.execute("ROLLBACK");
}

static void sc_named_execute_txn(PgConnection& c) {
    c.execute("BEGIN");
    c.executePortal("NO_SUCH_PORTAL_6424", 0, true);
    c.execute("ROLLBACK");
}

static void sc_named_describe_txn(PgConnection& c) {
    c.execute("BEGIN");
    c.describePortal("NO_SUCH_PORTAL_6424", true);
    c.execute("ROLLBACK");
}

// The backend aborted the transaction on its own error first, so it already agrees with
// the 'E' the local error reports; ROLLBACK over the extended protocol must still work.
static void sc_backend_already_aborted(PgConnection& c) {
    c.execute("BEGIN");
    c.execute("SELECT 1/0");
    c.executePortal("", 0, true);
    c.prepareStatement("", "ROLLBACK", false);
    c.bindStatement("", "", {}, {}, false);
    c.executePortal("", 0, true);
}

// The extended-protocol ROLLBACK an extended-only driver sends: Parse/Bind/Execute/Sync
// of the unnamed statement and portal.
static void ext_rollback(PgConnection& c, bool describe = false) {
    c.prepareStatement("", "ROLLBACK", false);
    c.bindStatement("", "", {}, {}, false);
    if (describe) c.describePortal("", false);
    c.executePortal("", 0, true);
}

// The local error leaves the backend at 'T'; the extended ROLLBACK must end the
// transaction and leave the session idle and usable.
static void sc_local_error_ext_rollback(PgConnection& c) {
    c.execute("BEGIN");
    c.executePortal("", 0, true);
    ext_rollback(c);
    c.execute("SELECT 1");
}

// Same, with Describe(portal) before the Execute (NoData for a transaction end).
static void sc_local_error_ext_rollback_describe(PgConnection& c) {
    c.execute("BEGIN");
    c.executePortal("", 0, true);
    ext_rollback(c, true);
    c.execute("SELECT 1");
}

// pgjdbc server-prepares its ROLLBACK after a few uses: Bind of the named statement
// with no Parse in the frame.
static void sc_local_error_named_ext_rollback(PgConnection& c) {
    c.prepareStatement("rollback_6424", "ROLLBACK", true);   // consumes its own ReadyForQuery
    c.execute("BEGIN");
    c.executePortal("", 0, true);
    c.bindStatement("rollback_6424", "", {}, {}, false);
    c.executePortal("", 0, true);
    c.execute("SELECT 1");
}

// Anything but a transaction end is still refused with 25P02, and the extended
// ROLLBACK that follows still recovers.
static void sc_local_error_ext_refused(PgConnection& c) {
    c.execute("BEGIN");
    c.executePortal("", 0, true);
    c.prepareStatement("", "SELECT 1", false);
    c.bindStatement("", "", {}, {}, false);
    c.executePortal("", 0, true);
    ext_rollback(c);
}

struct Case { const char* name; void (*fn)(PgConnection&); int n_ready; bool named; };

static const Case PARITY_CASES[] = {
    { "Execute of a missing unnamed portal, no transaction",            sc_unnamed_execute_idle,    1, false },
    { "Execute of a missing unnamed portal inside BEGIN",               sc_unnamed_execute_txn,     4, false },
    { "Describe of a missing unnamed portal inside BEGIN",              sc_unnamed_describe_txn,    4, false },
    { "local error after the backend aborted, extended ROLLBACK",       sc_backend_already_aborted, 4, false },
    { "local error at 'T', extended ROLLBACK",                          sc_local_error_ext_rollback, 4, false },
    { "local error at 'T', extended ROLLBACK with Describe(portal)",    sc_local_error_ext_rollback_describe, 4, false },
    { "local error at 'T', extended ROLLBACK of a named statement",     sc_local_error_named_ext_rollback, 4, false },
    { "local error at 'T', extended SELECT refused, extended ROLLBACK", sc_local_error_ext_refused, 4, false },
    { "Execute of a missing named portal inside BEGIN",                 sc_named_execute_txn,       3, true  },
    { "Describe of a missing named portal inside BEGIN",                sc_named_describe_txn,      3, true  },
};
static const int N_PARITY = (int)(sizeof(PARITY_CASES) / sizeof(PARITY_CASES[0]));

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

// BEGIN; INSERT; <a local error>; then the client sees what state it is in, keeps
// going, and finally sends COMMIT. PostgreSQL would answer the COMMIT with ROLLBACK and
// keep nothing. The INSERT reached the backend and the error did not, so it is up to
// ProxySQL to make sure the COMMIT cannot commit it.
static const int DURABILITY_ASSERTS = 4;
static void checkDurability(const char* what, void (*raise_local_error)(PgConnection&), const char* mode) {
    bool reported_aborted = false, stayed_aborted = false, not_committed = false, usable = false;
    try {
        PGConnPtr be = backendLibpq();
        if (!be || PQstatus(be.get()) != CONNECTION_OK || !truncateFixture(be.get()))
            throw std::runtime_error("cannot initialize durability fixture");
        auto c = connectProxy();
        c->execute("BEGIN");
        const auto begin = collect(*c, 1);
        c->execute("INSERT INTO " + FIXTURE + " VALUES (1)");
        const auto insert = collect(*c, 1);
        if (!errorCodes(insert).empty() || lastReadyState(begin) != 'T' || lastReadyState(insert) != 'T')
            throw std::runtime_error("cannot insert within the transaction before the local error");

        raise_local_error(*c);
        const auto err = collect(*c, 1);
        diag("  [%s] local error: %s (SQLSTATE %s, ReadyForQuery '%c')", what,
             streamSummary(err).c_str(), errorCodes(err).c_str(), lastReadyState(err));
        reported_aborted = !errorCodes(err).empty() && lastReadyState(err) == 'E';

        c->execute("SELECT 1");
        const auto select = collect(*c, 1);
        stayed_aborted = errorCodes(select) == "25P02" && lastReadyState(select) == 'E';

        c->execute("COMMIT");
        const auto commit = collect(*c, 1);
        diag("  [%s] COMMIT answered: %s (SQLSTATE '%s', ReadyForQuery '%c', ROLLBACK tag=%d)", what,
             streamSummary(commit).c_str(), errorCodes(commit).c_str(), lastReadyState(commit),
             (int)hasCommandTag(commit, "ROLLBACK"));
        const long long rows = fixtureRowCount(be.get());
        not_committed = hasCommandTag(commit, "ROLLBACK") && lastReadyState(commit) == 'I' && rows == 0;

        c->execute("INSERT INTO " + FIXTURE + " VALUES (2)");
        const auto after = collect(*c, 1);
        usable = errorCodes(after).empty() && lastReadyState(after) == 'I' && fixtureRowCount(be.get()) == 1;
        truncateFixture(be.get());
    } catch (const std::exception& e) {
        diag("[%s] durability probe failed: %s", what, e.what());
    }
    ok(reported_aborted, "%s inside BEGIN [%s]: ErrorResponse + ReadyForQuery('E')", what, mode);
    ok(stayed_aborted, "%s inside BEGIN [%s]: next statement rejected with 25P02 + 'E'", what, mode);
    ok(not_committed, "%s inside BEGIN [%s]: COMMIT answers ROLLBACK and the INSERT is not kept", what, mode);
    ok(usable, "%s inside BEGIN [%s]: session usable in autocommit afterwards", what, mode);
}

static void raise_rule_error(PgConnection& c) { c.execute(RULE_QUERY); }
static void raise_portal_error(PgConnection& c) { c.executePortal("", 0, true); }

// BEGIN; INSERT; <a local error>; then the transaction is ended over the extended
// protocol, as pgjdbc's rollback()/commit() do. Both must answer ROLLBACK and Z('I'),
// keep nothing, and leave the session usable. Before, the extended ROLLBACK/COMMIT got
// 25P02 + Z('E') at every Sync and the session never recovered.
static const int EXT_END_ASSERTS = 3;
static void checkExtendedEnd(const char* verb, const char* mode) {
    bool ended = false, not_kept = false, usable = false;
    try {
        PGConnPtr be = backendLibpq();
        if (!be || PQstatus(be.get()) != CONNECTION_OK || !truncateFixture(be.get()))
            throw std::runtime_error("cannot initialize durability fixture");
        auto c = connectProxy();
        c->execute("BEGIN");
        const auto begin = collect(*c, 1);
        c->execute("INSERT INTO " + FIXTURE + " VALUES (1)");
        const auto insert = collect(*c, 1);
        if (!errorCodes(insert).empty() || lastReadyState(begin) != 'T' || lastReadyState(insert) != 'T')
            throw std::runtime_error("cannot insert within the transaction before the local error");
        raise_portal_error(*c);
        const auto err = collect(*c, 1);
        if (lastReadyState(err) != 'E')
            throw std::runtime_error("the local error did not report 'E'");

        c->prepareStatement("", verb, false);
        c->bindStatement("", "", {}, {}, false);
        c->executePortal("", 0, true);
        const auto end = collect(*c, 1);
        diag("  [extended %s] answered: %s (SQLSTATE '%s', ReadyForQuery '%c')", verb,
             streamSummary(end).c_str(), errorCodes(end).c_str(), lastReadyState(end));
        ended = errorCodes(end).empty() && hasCommandTag(end, "ROLLBACK") && lastReadyState(end) == 'I';
        not_kept = fixtureRowCount(be.get()) == 0;

        c->execute("INSERT INTO " + FIXTURE + " VALUES (2)");
        const auto after = collect(*c, 1);
        usable = errorCodes(after).empty() && lastReadyState(after) == 'I' && fixtureRowCount(be.get()) == 1;
        truncateFixture(be.get());
    } catch (const std::exception& e) {
        diag("[extended %s] probe failed: %s", verb, e.what());
    }
    ok(ended, "local error at 'T' [%s]: extended-protocol %s answers ROLLBACK + ReadyForQuery('I')", mode, verb);
    ok(not_kept, "local error at 'T' [%s]: extended-protocol %s keeps nothing", mode, verb);
    ok(usable, "local error at 'T' [%s]: session usable in autocommit after the extended %s", mode, verb);
}

// A query rule refuses the first Parse of a frame; the INSERT queued behind it in the
// same frame must not run. It used to: the Parse path returned without discarding the
// frame, so the client got ErrorResponse + ReadyForQuery and then the INSERT ran --
// committed in autocommit, or sent to the pinned backend of a poisoned transaction.
static const int RULE_FRAME_ASSERTS = 4;
static void checkRuleErrorDiscardsFrame(const char* mode) {
    bool idle_only_error = false, idle_not_run = false, txn_only_error = false, txn_not_run = false;
    auto send_frame = [](PgConnection& c) {
        c.prepareStatement("", RULE_QUERY, false);
        c.prepareStatement("", "INSERT INTO " + FIXTURE + " VALUES (3)", false);
        c.bindStatement("", "", {}, {}, false);
        c.executePortal("", 0, true);
    };
    try {
        PGConnPtr be = backendLibpq();
        if (!be || PQstatus(be.get()) != CONNECTION_OK || !truncateFixture(be.get()))
            throw std::runtime_error("cannot initialize durability fixture");
        {
            auto c = connectProxy();
            send_frame(*c);
            const auto r = collect(*c, 1);
            diag("  [rule error mid-frame, autocommit] %s (SQLSTATE %s, ReadyForQuery %s)",
                 streamSummary(r).c_str(), errorCodes(r).c_str(), readyStates(r).c_str());
            // Whatever the INSERT would have produced arrives before this reply.
            c->execute("SELECT 1");
            const auto next = collect(*c, 1);
            idle_only_error = streamSummary(r) == "EZ" && lastReadyState(r) == 'I' &&
                              errorCodes(next).empty() && streamSummary(next) == "TDCZ";
            idle_not_run = fixtureRowCount(be.get()) == 0;
        }
        {
            auto c = connectProxy();
            c->execute("BEGIN");
            collect(*c, 1);
            send_frame(*c);
            const auto r = collect(*c, 1);
            diag("  [rule error mid-frame, in BEGIN] %s (SQLSTATE %s, ReadyForQuery %s)",
                 streamSummary(r).c_str(), errorCodes(r).c_str(), readyStates(r).c_str());
            c->execute("ROLLBACK");
            const auto rb = collect(*c, 1);
            txn_only_error = streamSummary(r) == "EZ" && lastReadyState(r) == 'E' &&
                             streamSummary(rb) == "CZ" && hasCommandTag(rb, "ROLLBACK") &&
                             lastReadyState(rb) == 'I';
            txn_not_run = fixtureRowCount(be.get()) == 0;
        }
        truncateFixture(be.get());
    } catch (const std::exception& e) {
        diag("[rule error mid-frame] probe failed: %s", e.what());
    }
    ok(idle_only_error, "error_msg rule on a Parse mid-frame [%s]: only ErrorResponse + ReadyForQuery('I'), "
       "nothing else answered", mode);
    ok(idle_not_run, "error_msg rule on a Parse mid-frame [%s]: the INSERT queued behind it never ran", mode);
    ok(txn_only_error, "error_msg rule on a Parse mid-frame in BEGIN [%s]: only ErrorResponse + "
       "ReadyForQuery('E'), then ROLLBACK answers ROLLBACK + 'I'", mode);
    ok(txn_not_run, "error_msg rule on a Parse mid-frame in BEGIN [%s]: the INSERT never reached the backend", mode);
}

// ------------------------------------------------------------------ main

static const char* MODE_NAME[2] = { "libpq backend protocol", "native backend protocol" };
static const int PER_MODE = N_PARITY + 2 * DURABILITY_ASSERTS + 2 * EXT_END_ASSERTS + RULE_FRAME_ASSERTS;

int main(int, char**) {
    plan(PER_MODE * 2);

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
        setRule(admin, false);
        if (!saved_native.empty())
            setNativeMode(admin, saved_native == "true" || saved_native == "1");
        flushBackendPool(admin, BACKEND_HG, saved_servers);
        auth.restore();
    };
    if (!auth.ok) { cleanup(); BAIL_OUT("failed to force frontend cleartext auth"); }
    if (saved_servers.empty()) { cleanup(); BAIL_OUT("no pgsql_servers rows for hostgroup %d", BACKEND_HG); }
    if (!setRule(admin, true)) { cleanup(); BAIL_OUT("cannot install the error_msg query rule"); }

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
            skip(PER_MODE, "native backend protocol is unavailable in v3.0");
            continue;
        }
        diag("================ %s ================", MODE_NAME[mode]);
        if (native_supported && !setNativeMode(admin, native)) { cleanup(); BAIL_OUT("cannot set the backend protocol"); }
        if (!flushBackendPool(admin, BACKEND_HG, saved_servers)) {
            cleanup();
            BAIL_OUT("cannot flush the backend pool between protocol phases");
        }

        // ---- parity: the proxy's stream must be PostgreSQL's stream -----------
        for (const auto& kase : PARITY_CASES) {
            std::string oerr, perr;
            std::vector<Msg> oracle = runLeg(false, kase.fn, kase.n_ready, oerr);
            std::vector<Msg> proxy  = runLeg(true,  kase.fn, kase.n_ready, perr);
            if (!oerr.empty() || !perr.empty()) {
                ok(false, "%s [%s]: leg failed -- oracle:'%s' proxy:'%s'",
                   kase.name, MODE_NAME[mode], oerr.c_str(), perr.c_str());
                continue;
            }
            diag("  %s: oracle %s (SQLSTATE %s, ReadyForQuery %s); proxy %s (SQLSTATE %s, ReadyForQuery %s)",
                 kase.name,
                 streamSummary(oracle).c_str(), errorCodes(oracle).c_str(), readyStates(oracle).c_str(),
                 streamSummary(proxy).c_str(), errorCodes(proxy).c_str(), readyStates(proxy).c_str());
            if (kase.named && !native) {
                // libpq mode refuses every named portal with 0A000 instead of looking it
                // up. The refusal is still an error inside the transaction block.
                const bool same_states = readyStates(oracle) == readyStates(proxy);
                ok(same_states && errorCodes(proxy) == "0A000",
                   "%s [%s]: refused with 0A000, transaction states %s as direct PostgreSQL's %s",
                   kase.name, MODE_NAME[mode], readyStates(proxy).c_str(), readyStates(oracle).c_str());
                continue;
            }
            std::string why;
            const bool same = sameStream(oracle, proxy, why);
            ok(same, "%s [%s]: identical to direct PostgreSQL%s%s",
               kase.name, MODE_NAME[mode], same ? "" : " -- ", same ? "" : why.c_str());
        }

        // ---- durability: COMMIT after a local error must not commit ----------
        checkDurability("query rule error_msg", raise_rule_error, MODE_NAME[mode]);
        checkDurability("Execute of a missing portal", raise_portal_error, MODE_NAME[mode]);
        checkExtendedEnd("ROLLBACK", MODE_NAME[mode]);
        checkExtendedEnd("COMMIT", MODE_NAME[mode]);
        checkRuleErrorDiscardsFrame(MODE_NAME[mode]);
    }

    {
        PGConnPtr be = backendLibpq();
        if (be && PQstatus(be.get()) == CONNECTION_OK)
            PQclear(PQexec(be.get(), ("DROP TABLE IF EXISTS " + FIXTURE).c_str()));
    }
    cleanup();
    return exit_status();
}
