#include "prepared_owned_fixture.h"
/** Live read-only PostgreSQL admin prepared-statement acceptance test.
 * Set TAP_PGSQL_ADMINHOST, TAP_PGSQL_ADMINPORT, TAP_PGSQL_ADMINUSERNAME,
 * TAP_PGSQL_ADMINPASSWORD. Optional TAP_PGSQL_STATSUSERNAME and
 * TAP_PGSQL_STATSPASSWORD run the same libpq checks against stats.
 */
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "tap.h"

static const char* env(const char* name) { return getenv(name); }
static bool state(PGresult* r, const char* code) {
    const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
    return PQresultStatus(r) == PGRES_FATAL_ERROR && s && !strcmp(s, code);
}
static bool rows(PGresult* r, const char* a, const char* b) {
    return PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 &&
        PQnfields(r) == 2 && !PQgetisnull(r, 0, 0) && !PQgetisnull(r, 0, 1) &&
        !strcmp(PQgetvalue(r, 0, 0), a) && !strcmp(PQgetvalue(r, 0, 1), b);
}
static void libpq_checks(const char* host, const char* port, const char* user, const char* pass, bool stats) {
    const char* keys[] = {"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout", nullptr};
    const char* vals[] = {host, port, user, pass, "main", "disable", "3", nullptr};
    PGconn* c = PQconnectdbParams(keys, vals, 0);
    if (PQstatus(c) != CONNECTION_OK) BAIL_OUT("libpq connection failed: %s", PQerrorMessage(c));
    Oid types[] = {20, 25};
    PGresult* r = PQprepare(c, "ordered", "SELECT $2 AS text_value, $1 AS int_value", 2, types);
    bool prepared = PQresultStatus(r) == PGRES_COMMAND_OK;
    ok(prepared, "prepare named typed statement: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQdescribePrepared(c, "ordered");
    ok(PQresultStatus(r) == PGRES_COMMAND_OK && PQnparams(r) == 2 && PQparamtype(r, 0) == 20 && PQparamtype(r, 1) == 25 && PQnfields(r) == 2 && PQftype(r, 0) == 25 && PQftype(r, 1) == 25,
        "describe preserves parameter OIDs and dynamic expression TEXT metadata");
    PQclear(r);
    const char* values[] = {"42", "x'); DROP TABLE mysql_servers; --"};
    r = PQexecPrepared(c, "ordered", 2, values, nullptr, nullptr, 0);
    ok(rows(r, values[1], values[0]), "bind uses parameter positions and treats SQL-shaped text literally");
    PQclear(r);
    values[0] = "-7"; values[1] = "";
    r = PQexecPrepared(c, "ordered", 2, values, nullptr, nullptr, 0);
    ok(rows(r, "", "-7"), "repeat bind distinguishes empty text");
    PQclear(r);
    values[1] = nullptr;
    r = PQexecPrepared(c, "ordered", 2, values, nullptr, nullptr, 0);
    ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 && PQgetisnull(r, 0, 0) && !strcmp(PQgetvalue(r, 0, 1), "-7"), "NULL remains distinct from empty text");
    PQclear(r);
    values[1] = "Gr\xc3\xbc\xc3\x9f";
    r = PQexecPrepared(c, "ordered", 2, values, nullptr, nullptr, 0);
    ok(rows(r, values[1], "-7"), "UTF-8 text round trips");
    PQclear(r);
    const char number[] = {0,0,0,0,0,0,0,42};
    const char utf8[] = "Gr\xc3\xbc\xc3\x9f";
    const char* binary[] = {number, utf8}; int lengths[] = {8, static_cast<int>(sizeof(utf8) - 1)}; int formats[] = {1, 1};
    r = PQexecPrepared(c, "ordered", 2, binary, lengths, formats, 0);
    ok(rows(r, utf8, "42"), "binary int8 and UTF-8 text parameters bind correctly");
    PQclear(r);
    const char bad[] = {char(0xff)}; binary[1] = bad; lengths[1] = 1;
    r = PQexecPrepared(c, "ordered", 2, binary, lengths, formats, 0);
    ok(prepared && state(r, "22021") && PQstatus(c) == CONNECTION_OK, "invalid binary TEXT is rejected without disconnecting");
    PQclear(r);
    Oid blob_type = 17;
    r = PQprepare(c, "blob", "SELECT $1 = $1", 1, &blob_type);
    bool blob_prepared = PQresultStatus(r) == PGRES_COMMAND_OK; PQclear(r);
    const char blob[] = {0, 1, char(0xff)};
    const char* blob_value[] = {blob}; int blob_length[] = {3}; int blob_format[] = {1};
    r = PQexecPrepared(c, "blob", 1, blob_value, blob_length, blob_format, 0);
    ok(blob_prepared && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 && !strcmp(PQgetvalue(r, 0, 0), "1"), "binary bytea with NUL binds as a blob"); PQclear(r);
    Oid numeric_type = 1700;
    r = PQprepare(c, "numeric", "SELECT $1", 1, &numeric_type);
    bool numeric_rejected = false;
    bool numeric_prepared = PQresultStatus(r) == PGRES_COMMAND_OK; PQclear(r);
    if (numeric_prepared) {
        const char numeric[] = {0, 0, 0, 0, 0, 0, 0, 0};
        const char* value[] = {numeric}; int len[] = {8}; int format[] = {1};
        r = PQexecPrepared(c, "numeric", 1, value, len, format, 0);
        numeric_rejected = state(r, "0A000"); PQclear(r);
    }
    ok(numeric_rejected && PQstatus(c) == CONNECTION_OK, "binary numeric returns 0A000 without disconnect");
    const char* metadata_sql = stats
        ? "SELECT hostgroup FROM stats_mysql_connection_pool LIMIT 0"
        : "SELECT weight FROM mysql_servers LIMIT 0";
    r = PQprepare(c, "table_metadata", metadata_sql, 0, nullptr);
    bool table_prepared = PQresultStatus(r) == PGRES_COMMAND_OK;
    PQclear(r);
    r = PQdescribePrepared(c, "table_metadata");
    ok(table_prepared && PQresultStatus(r) == PGRES_COMMAND_OK && PQnfields(r) == 1 &&
        PQftype(r, 0) == 20, "known %s INTEGER column describes as PostgreSQL int8",
        stats ? "STATS" : "Admin");
    PQclear(r);
    Oid bool_oid = 16;
    r = PQprepare(c, "bool_value", "SELECT $1", 1, &bool_oid);
    bool bool_prepared = PQresultStatus(r) == PGRES_COMMAND_OK; PQclear(r);
    const char* bool_values[] = {"true"};
    r = bool_prepared ? PQexecPrepared(c, "bool_value", 1, bool_values, nullptr, nullptr, 0) : nullptr;
    ok(r && PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1 && std::string(PQgetvalue(r, 0, 0)) == "1", "BOOL parameter binds through SQLite as integer");
    if (r) PQclear(r);
    struct Unsupported { Oid oid; const char* name; } unsupported[] = {{1082,"date"}};
    for (const auto& u : unsupported) {
        r = PQprepare(c, u.name, "SELECT $1", 1, &u.oid);
        bool rejected = state(r, "0A000"); PQclear(r);
        ok(rejected && PQstatus(c) == CONNECTION_OK, "unsupported %s type returns 0A000 without disconnect", u.name);
    }
    Oid unknown = 0;
    r = PQprepare(c, "unknown", "SELECT $1", 1, &unknown);
    ok(state(r, "42P18"), "unresolved parameter type returns 42P18"); PQclear(r);
    const char* policies[] = {"LOAD MYSQL SERVERS TO RUNTIME", "PRAGMA table_info(mysql_servers)", "SELECT load_extension('x')"};
    for (const char* sql : policies) {
        r = PQprepare(c, "policy", sql, 0, nullptr);
        ok(PQresultStatus(r) == PGRES_FATAL_ERROR && PQstatus(c) == CONNECTION_OK, "read-only policy rejects %s", sql); PQclear(r);
    }
    for (const char* sql : {"BEGIN", "ROLLBACK"}) {
        r = PQexec(c, sql);
        ok(state(r, "0A000") && PQtransactionStatus(c) == PQTRANS_IDLE,
            "explicit transaction command is refused while idle: %s", sql);
        PQclear(r);
    }
    r = PQprepare(c, "write", "DELETE FROM mysql_servers WHERE 1=0", 0, nullptr);
    ok(PQresultStatus(r) == PGRES_FATAL_ERROR && PQstatus(c) == CONNECTION_OK,
        "prepared DML is refused by the initial read-only PostgreSQL policy");
    PQclear(r);
    const char* latin_keys[] = {"host", "port", "user", "password", "dbname", "sslmode",
        "connect_timeout", "client_encoding", nullptr};
    const char* latin_values[] = {host, port, user, pass, "main", "disable", "3", "LATIN1", nullptr};
    PGconn* latin = PQconnectdbParams(latin_keys, latin_values, 0);
    if (PQstatus(latin) != CONNECTION_OK)
        BAIL_OUT("non-UTF8 fixture connection failed: %s", PQerrorMessage(latin));
    r = PQprepare(latin, "encoding", "SELECT 1", 0, nullptr);
    ok(state(r, "0A000") && PQstatus(latin) == CONNECTION_OK,
        "prepared queries explicitly refuse non-UTF8 startup encoding");
    PQclear(r);
    PQfinish(latin);
    r = PQexec(c, "SELECT 1");
    ok(PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1, "connection remains usable after rejected statements");
    PQclear(r); PQfinish(c);
}
static std::string messages(PgConnection& c, int quiet = 100) {
    std::string s;
    for (const auto& m : c.readUntilQuiet(quiet)) s += m.first;
    return s;
}
static void wire_checks(const char* host, const char* port, const char* user, const char* pass) {
    try {
        PgConnection c(2000); c.connect(host, atoi(port), "main", user, pass);
        c.prepareStatement("s", "SELECT 1 UNION ALL SELECT 2", false);
        c.sendSync();
        std::string seq = messages(c);
        ok(seq == "1Z", "named statement parse and Sync: %s", seq.c_str());
        c.bindStatement("s", "p1", {}, {}, false); c.bindStatement("s", "p2", {}, {}, false);
        c.executePortal("p1", 1, false); c.sendFlush(); seq = messages(c);
        ok(seq == "22Ds", "independent portals and first row suspend before Sync: %s", seq.c_str());
        c.executePortal("p2", 2, false); c.sendFlush(); seq = messages(c);
        ok(seq == "DDs", "exact row limit suspends portal: %s", seq.c_str());
        c.executePortal("p2", 2, false); c.sendFlush(); seq = messages(c);
        ok(seq == "C", "resuming at exact boundary completes with zero rows: %s", seq.c_str());
        c.executePortal("p1", 0, false); c.sendSync(); seq = messages(c);
        ok(seq == "DCZ", "independent portal continues and Sync returns ready: %s", seq.c_str());
        c.bindStatement("s", "p3", {}, {}, false); c.executePortal("p3", 0, false); c.sendSync(); seq = messages(c);
        ok(seq == "2DDCZ", "named statement survives Sync: %s", seq.c_str());
        c.closeStatement("missing", false); c.closePortal("missing", false); c.sendSync(); seq = messages(c);
        ok(seq == "33Z", "closing unknown statement and portal succeeds: %s", seq.c_str());
        c.prepareStatement("bad", "LOAD MYSQL SERVERS TO RUNTIME", false); c.sendFlush(); seq = messages(c);
        ok(seq == "E", "unsupported Parse and Flush sends one error without ready: %s", seq.c_str());
        c.bindStatement("s", "discard", {}, {}, false); c.sendQuery("SELECT 1"); c.sendSync(); seq = messages(c);
        ok(seq == "Z", "messages including simple Query discarded until Sync: %s", seq.c_str());
    } catch (const std::exception& e) {
        diag("wire protocol test failed: %s", e.what());
        BAIL_OUT("wire protocol connection failed");
    }
}
int main() {
    prepared_owned_fixture::Fixture fixture;
    const char* host = env("TAP_PGSQL_ADMINHOST"), *port = env("TAP_PGSQL_ADMINPORT");
    const char* user = env("TAP_PGSQL_ADMINUSERNAME"), *pass = env("TAP_PGSQL_ADMINPASSWORD");
    if (!host || !port || !user || !pass) { diag("Set TAP_PGSQL_ADMINHOST/ADMINPORT/ADMINUSERNAME/ADMINPASSWORD"); return EXIT_FAILURE; }
    const char* su = env("TAP_PGSQL_STATSUSERNAME"), *sp = env("TAP_PGSQL_STATSPASSWORD");
    if (!!su != !!sp) { diag("Set both optional stats credentials"); return EXIT_FAILURE; }
    alarm(60); // Bound connect, DNS and libpq operations as well as socket reads.
    plan(31 + (su ? 22 : 0));
    libpq_checks(host, port, user, pass, false); wire_checks(host, port, user, pass);
    if (su) libpq_checks(host, port, su, sp, true);
    return exit_status();
}
