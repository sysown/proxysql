/**
 * @file pgsql-native_scram_mechanism-t.cpp
 * @brief Which SASL mechanism the native backend path selects, across the
 *        offered-mechanisms x backend-TLS matrix.
 *
 * WHY THIS EXISTS
 * ---------------
 * pgsql-native_auth_matrix-t already proves native logins SUCCEED over SCRAM with
 * and without TLS, for every stored-secret type. What no test checks is WHICH
 * mechanism was chosen, and that gap is not cosmetic: a login succeeds whether
 * ProxySQL picks SCRAM-SHA-256 or SCRAM-SHA-256-PLUS, because PostgreSQL accepts
 * plain SCRAM over an encrypted connection perfectly happily. So a build that
 * silently stopped upgrading to -PLUS over TLS -- dropping channel binding, the
 * one defence against a man-in-the-middle backend -- would pass every existing
 * test. pgsql-native_tls-t even claims a successful TLS login proves channel
 * binding; it does not, and this file is what actually proves it.
 *
 * Two further rows have no coverage at all: the ones where the native path must
 * REFUSE. Those used to divert the connection to libpq, which cannot complete them
 * either, so the observable result was a slower failure with a vaguer message. The
 * native path now fails them in place, with a message naming the fix, and that is
 * what is asserted here.
 *
 * THE MATRIX (mirrors the selection block in lib/PgSQL_Connection.cpp)
 * -------------------------------------------------------------------
 *   offered            backend TLS   expected
 *   SCRAM-SHA-256      no            SCRAM-SHA-256
 *   SCRAM-SHA-256      yes           SCRAM-SHA-256   (nothing better on offer)
 *   both               no            SCRAM-SHA-256   (no certificate to bind to)
 *   both               yes           SCRAM-SHA-256-PLUS   <-- the upgrade
 *   -PLUS only         yes           SCRAM-SHA-256-PLUS
 *   -PLUS only         no            refuse, no libpq fallback
 *   neither            no            refuse, no libpq fallback
 *
 * A real PostgreSQL can only produce rows 1-4: it advertises -PLUS only on an
 * already-encrypted connection, and always alongside plain SCRAM. Rows 5-7 need a
 * server that advertises whatever we tell it to, which is what the mock is for.
 *
 * HOW THE CHOICE IS OBSERVED
 * --------------------------
 * The mechanism name travels in the client's SASLInitialResponse. The mock records
 * it (PgSQL_Mock_Backend::selected_mechanism) and the test reads it back. Nothing
 * in ProxySQL logs it, and the login outcome cannot distinguish the two.
 *
 * WHY EACH CASE ALSO COUNTS CONNECTIONS
 * -------------------------------------
 * Recording the mechanism is not by itself proof of which client produced it, so a
 * case that expects a native exchange also requires the mock to have accepted exactly
 * one connection for the attempt -- the shape the native path produces, and what any
 * retry or second client would break.
 *
 * INFRA
 * -----
 * legacy-g1. The mock listens inside the test-runner container on its own
 * hostgroup, so nothing here can disturb the real backend.
 *
 * Runtime state is restored in memory at the end -- never SAVE ... TO DISK.
 */
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>
#include <vector>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_mock_backend.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

// Its own hostgroup and user: a mock that refuses every connection must not be
// able to shun anything the rest of the group depends on.
static const int MOCK_HG = 48;
static const char* MOCK_USER = "scram_mech_user";
static const char* MOCK_PASS = "scram_mech_pw";

static PGConnPtr openConn(const char* host, int port, const char* user,
                          const char* pass, const char* db, const char* sslmode) {
    std::stringstream ss;
    ss << "host=" << host << " port=" << port << " user=" << user << " password=" << pass;
    if (db && *db) ss << " dbname=" << db;
    ss << " sslmode=" << sslmode << " connect_timeout=10";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static PGConnPtr createAdminConn() {
    return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port,
                    cl.admin_username, cl.admin_password, nullptr, "disable");
}

static bool execAdmin(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
    PQclear(r);
    return good;
}

static bool setVar(PGconn* admin, const std::string& name, const std::string& val) {
    return execAdmin(admin, "SET " + name + "='" + val + "'") &&
           execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

// Re-registering the server row drops every pooled connection for the hostgroup.
// Without it a case could be served from the previous case's connection, so its
// script would never run and its verdict would describe the wrong exchange.
static bool resetMockPool(PGconn* admin, const std::string& ip, uint16_t port, int use_ssl) {
    std::stringstream del, ins;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
    if (!execAdmin(admin, del.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
        return false;
    ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,use_ssl,comment) "
        << "VALUES (" << MOCK_HG << ",'" << ip << "'," << port << ",4," << use_ssl
        << ",'scram mechanism mock')";
    if (!execAdmin(admin, ins.str()) || !execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME"))
        return false;
    usleep(150000);
    return true;
}

static std::string acceptedHandshake() {
    return pgmb_auth_ok() +
           pgmb_parameter_status("server_version", "16.2") +
           pgmb_parameter_status("client_encoding", "UTF8") +
           pgmb_backend_key_data(4242, 987654321) +
           pgmb_ready_for_query('I');
}

// A full SCRAM handshake advertising `mechs`, optionally preceded by a real TLS
// handshake, then one answered query.
static std::vector<Step> scriptFor(const std::vector<std::string>& mechs, bool tls) {
    std::vector<Step> s;
    if (tls) {
        s.push_back(step_expect_startup());   // the 8-byte SSLRequest
        s.push_back(step_send("S"));
        s.push_back(step_tls_accept());
    }
    s.push_back(step_expect_startup());       // the real StartupMessage
    s.push_back(step_send(pgmb_auth_sasl(mechs)));
    s.push_back(step_scram_server_first(false));
    s.push_back(step_scram_server_final(false));
    s.push_back(step_send(acceptedHandshake()));
    s.push_back(step_expect_query());
    s.push_back(step_send(pgmb_simple_result("answer", "42", 1) + pgmb_ready_for_query('I')));
    return s;
}

// Same, for the rows the native path must refuse. The SCRAM step is present on
// purpose: if ProxySQL wrongly sent a SASLInitialResponse anyway, the mock records
// the mechanism and the case fails on a non-empty name rather than passing quietly.
static std::vector<Step> refusalScriptFor(const std::vector<std::string>& mechs) {
    return { step_expect_startup(),
             step_send(pgmb_auth_sasl(mechs)),
             step_scram_server_first(false),
             step_sleep(1000) };
}

static bool queryThroughProxy(std::string& err, std::string& answer) {
    auto c = openConn(cl.pgsql_host, cl.pgsql_port, MOCK_USER, MOCK_PASS, "postgres", "disable");
    if (!c || PQstatus(c.get()) != CONNECTION_OK) {
        err = c ? PQerrorMessage(c.get()) : "null conn";
        return false;
    }
    PGresult* r = PQexec(c.get(), "SELECT 42 AS answer");
    const bool good = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0);
    if (good) answer = PQgetvalue(r, 0, 0); else err = PQerrorMessage(c.get());
    PQclear(r);
    return good;
}

static std::string oneLine(const std::string& s) {
    const size_t nl = s.find('\n');
    return nl == std::string::npos ? s : s.substr(0, nl);
}

int main(int, char**) {
    // 2 harness self-tests (libpq as an independent oracle) + 7 matrix rows.
    plan(9);

    if (cl.getEnv()) return exit_status();

    auto adminOwner = createAdminConn();
    if (!adminOwner || PQstatus(adminOwner.get()) != CONNECTION_OK)
        BAIL_OUT("cannot proceed without an admin connection");
    PGconn* admin = adminOwner.get();

    // A mock that refuses connections would otherwise be shunned before the
    // refusal rows run, and they would fail as "no backend" instead.
    if (!setVar(admin, "pgsql-monitor_enabled", "false")) BAIL_OUT("cannot disable the monitor");
    if (!setVar(admin, "pgsql-shun_on_failures", "10000")) BAIL_OUT("cannot raise shun_on_failures");
    setVar(admin, "pgsql-connect_timeout_server_max", "5000");
    if (!setVar(admin, "pgsql-use_native_backend_protocol", "true"))
        BAIL_OUT("cannot enable the native backend protocol");

    PgSQL_Mock_Backend mock;
    mock.set_scram_password(MOCK_PASS);
    if (!mock.start()) BAIL_OUT("mock backend failed to listen");

    const std::string myip = pgmb_local_ip_towards(cl.pgsql_host, cl.pgsql_port);
    if (myip.empty()) BAIL_OUT("could not discover this container's IP toward ProxySQL");
    diag("mock backend listening on %s:%u (hostgroup %d)", myip.c_str(), mock.port(), MOCK_HG);

    {
        std::stringstream u;
        u << "INSERT OR REPLACE INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('"
          << MOCK_USER << "','" << MOCK_PASS << "',1," << MOCK_HG << ")";
        if (!execAdmin(admin, u.str()) || !execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME"))
            BAIL_OUT("could not register the mock user");
    }

    // ---- harness self-tests ------------------------------------------------
    // The verdicts below are only as good as the fixture. libpq is the independent
    // oracle: if it cannot complete these exchanges, a ProxySQL failure would say
    // nothing about ProxySQL.
    {
        mock.set_script(scriptFor({ "SCRAM-SHA-256" }, false));
        mock.reset_stats();
        auto c = openConn(myip.c_str(), mock.port(), MOCK_USER, MOCK_PASS, "postgres", "disable");
        const bool connected = (c && PQstatus(c.get()) == CONNECTION_OK);
        ok(connected, "harness: libpq completes plain SCRAM-SHA-256 against the mock (chose '%s')%s%s",
           mock.selected_mechanism().c_str(),
           connected ? "" : ": ", connected ? "" : oneLine(PQerrorMessage(c.get())).c_str());
    }
    {
        // -PLUS over TLS: proves the mock's certificate can be fingerprinted and that
        // its SCRAM accepts a channel-bound exchange. Without this, row 5 failing
        // would be ambiguous between ProxySQL and the fixture.
        mock.set_script(scriptFor({ "SCRAM-SHA-256-PLUS" }, true));
        mock.reset_stats();
        auto c = openConn(myip.c_str(), mock.port(), MOCK_USER, MOCK_PASS, "postgres", "require");
        const bool connected = (c && PQstatus(c.get()) == CONNECTION_OK);
        ok(connected && mock.selected_mechanism() == "SCRAM-SHA-256-PLUS",
           "harness: libpq completes SCRAM-SHA-256-PLUS over TLS against the mock (chose '%s')%s%s",
           mock.selected_mechanism().c_str(),
           connected ? "" : ": ", connected ? "" : oneLine(PQerrorMessage(c.get())).c_str());
    }

    // ---- the matrix --------------------------------------------------------
    struct Row {
        const char* name;
        std::vector<std::string> offered;
        int use_ssl;
        const char* expect_mech;   // nullptr => the connect must be refused
    };
    const std::vector<Row> rows = {
        { "plain offered, no TLS",   { "SCRAM-SHA-256" },                        0, "SCRAM-SHA-256" },
        { "plain offered, TLS",      { "SCRAM-SHA-256" },                        1, "SCRAM-SHA-256" },
        { "both offered, no TLS",    { "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS" },  0, "SCRAM-SHA-256" },
        { "both offered, TLS",       { "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS" },  1, "SCRAM-SHA-256-PLUS" },
        { "-PLUS only, TLS",         { "SCRAM-SHA-256-PLUS" },                   1, "SCRAM-SHA-256-PLUS" },
        { "-PLUS only, no TLS",      { "SCRAM-SHA-256-PLUS" },                   0, nullptr },
        { "no usable mechanism",     { "GSSAPI", "ANONYMOUS" },                  0, nullptr },
    };

    for (const auto& row : rows) {
        const bool must_refuse = (row.expect_mech == nullptr);
        if (!resetMockPool(admin, myip, mock.port(), row.use_ssl))
            BAIL_OUT("could not point the hostgroup at the mock for '%s'", row.name);
        mock.set_script(must_refuse ? refusalScriptFor(row.offered)
                                    : scriptFor(row.offered, row.use_ssl != 0));
        mock.reset_stats();

        std::string err, answer;
        const bool served = queryThroughProxy(err, answer);
        const std::string chose = mock.selected_mechanism();
        const int conns = mock.connections_accepted();

        if (must_refuse) {
            // Refusing means the client is not served AND ProxySQL never sent a
            // SASLInitialResponse naming a mechanism it cannot finish. The second half
            // matters: starting an exchange and abandoning it would also leave the
            // client unserved, but for a different and worse reason.
            ok(!served && chose.empty(),
               "%s: native refuses in place (served=%d, mechanism sent='%s') [%s]",
               row.name, (int)served, chose.c_str(),
               served ? "unexpectedly served" : oneLine(err).c_str());
        } else {
            // Exactly one backend connection. The mechanism name on its own would not
            // prove the native path chose it -- any second client of this mock could
            // have picked the same name -- and one connection per client attempt is the
            // shape the native path produces.
            ok(served && answer == "42" && chose == row.expect_mech && conns == 1,
               "%s: chose '%s' (expected '%s'), served=%d answer='%s', backend conns=%d%s%s",
               row.name, chose.empty() ? "-" : chose.c_str(), row.expect_mech,
               (int)served, answer.c_str(), conns,
               served ? "" : " -- ", served ? "" : oneLine(err).c_str());
        }
    }

    // ---- restore -----------------------------------------------------------
    {
        std::stringstream del;
        del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << MOCK_HG;
        execAdmin(admin, del.str());
        execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME");
        execAdmin(admin, std::string("DELETE FROM pgsql_users WHERE username='") + MOCK_USER + "'");
        execAdmin(admin, "LOAD PGSQL USERS TO RUNTIME");
        setVar(admin, "pgsql-monitor_enabled", "true");
    }
    mock.stop();
    return exit_status();
}
