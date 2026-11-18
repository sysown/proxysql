#include "prepared_owned_fixture.h"
/** Live read-only PostgreSQL admin prepared-statement acceptance test.
 * Set TAP_PGSQL_ADMINHOST, TAP_PGSQL_ADMINPORT, TAP_PGSQL_ADMINUSERNAME,
 * TAP_PGSQL_ADMINPASSWORD. Optional TAP_PGSQL_STATSUSERNAME and
 * TAP_PGSQL_STATSPASSWORD run the same libpq checks against stats.
 */
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <utility>
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

static PGconn* connect_user(const char* host, const char* port, const char* user, const char* pass) {
    const char* keys[] = {"host", "port", "user", "password", "dbname", "sslmode", "connect_timeout", nullptr};
    const char* values[] = {host, port, user, pass, "main", "disable", "3", nullptr};
    return PQconnectdbParams(keys, values, 0);
}

static bool admin_login_denied(const char* host, const char* port, const char* user, const char* pass) {
    PGconn* connection = connect_user(host, port, user, pass);
    const char* error = connection ? PQerrorMessage(connection) : "";
    const bool denied = connection && PQstatus(connection) == CONNECTION_BAD &&
        (std::strstr(error, "password authentication failed") || std::strstr(error, "Access denied for user"));
    if (!denied) diag("expected a PostgreSQL authentication rejection: %s", error);
    PQfinish(connection);
    return denied;
}

static void libpq_checks(const char* host, const char* port, const char* user, const char* pass, bool stats) {
    PGconn* c = connect_user(host, port, user, pass);
    if (PQstatus(c) != CONNECTION_OK) BAIL_OUT("libpq connection failed: %s", PQerrorMessage(c));
    PGresult* role_result = PQprepare(c, "configuration",
        "SELECT hostgroup_id FROM mysql_servers LIMIT 0", 0, nullptr);
    ok(PQresultStatus(role_result) == (stats ? PGRES_FATAL_ERROR : PGRES_COMMAND_OK) &&
       PQstatus(c) == CONNECTION_OK,
       "%s prepared access to the Admin configuration schema: %s",
       stats ? "STATS is denied" : "Admin has", PQresultErrorMessage(role_result));
    PQclear(role_result);
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
        r = PQprepare(c, "txn", sql, 0, nullptr);
        ok(PQresultStatus(r) == PGRES_FATAL_ERROR && PQtransactionStatus(c) == PQTRANS_IDLE,
            "prepared transaction command is refused while idle: %s", sql);
        PQclear(r);
    }
    r = PQprepare(c, "write", "DELETE FROM mysql_servers WHERE 1=0", 0, nullptr);
    ok(PQresultStatus(r) == PGRES_FATAL_ERROR && PQstatus(c) == CONNECTION_OK,
        "prepared DML is refused by the initial read-only PostgreSQL policy");
    PQclear(r);
    if (!stats) {
        r = PQexec(c, "PROXY_SELECT hostgroup_id, hostname, port, CASE status WHEN 'ONLINE' "
                      "THEN 'ONLINE' WHEN 'SHUNNED' THEN 'ONLINE' WHEN 'OFFLINE_SOFT' THEN "
                      "'OFFLINE_SOFT' WHEN 'OFFLINE_HARD' THEN 'OFFLINE_HARD' ELSE status END status, "
                      "weight, compression, max_connections, max_replication_lag, use_ssl, "
                      "max_latency_ms, comment FROM runtime_pgsql_servers "
                      "WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port");
        ok(PQresultStatus(r) == PGRES_TUPLES_OK &&
               std::strncmp(PQcmdStatus(r), "SELECT", 6) == 0,
           "Cluster CASE END query keeps its Admin response after prepare: %s",
           PQresultErrorMessage(r));
        PQclear(r);

        PGconn *legacy = connect_user(host, port, user, pass);
        if (!legacy || PQstatus(legacy) != CONNECTION_OK)
            BAIL_OUT("cannot connect second Admin client for transaction test");
        r = PQprepare(c, "before_txn", "SELECT 1", 0, nullptr);
        ok(PQresultStatus(r) == PGRES_COMMAND_OK, "prepare before a legacy transaction");
        PQclear(r);
        r = PQexec(legacy, "BEGIN");
        ok(PQresultStatus(r) == PGRES_COMMAND_OK, "legacy Admin BEGIN keeps its existing response");
        PQclear(r);
        r = PQexecPrepared(c, "before_txn", 0, nullptr, nullptr, nullptr, 0);
        ok(PQresultStatus(r) == PGRES_TUPLES_OK, "legacy BEGIN leaves native autocommit on");
        PQclear(r);
        r = PQexec(legacy, "ROLLBACK");
        ok(PQresultStatus(r) == PGRES_COMMAND_OK, "legacy Admin ROLLBACK keeps its existing response");
        PQclear(r);
        r = PQexec(legacy, "SAVEPOINT admin_prepare_test");
        ok(PQresultStatus(r) == PGRES_COMMAND_OK, "legacy savepoint opens a native transaction");
        PQclear(r);
        r = PQexecPrepared(c, "before_txn", 0, nullptr, nullptr, nullptr, 0);
        ok(state(r, "25000"), "prepared traffic refuses to join another client's native transaction: %s",
           PQresultErrorMessage(r));
        PQclear(r);
        r = PQexec(legacy, "RELEASE SAVEPOINT admin_prepare_test");
        ok(PQresultStatus(r) == PGRES_COMMAND_OK, "legacy release restores native autocommit");
        PQclear(r);
        r = PQexecPrepared(c, "before_txn", 0, nullptr, nullptr, nullptr, 0);
        ok(PQresultStatus(r) == PGRES_TUPLES_OK, "prepared traffic recovers after the native transaction");
        PQclear(r);
        PQfinish(legacy);
    }
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

static void schema_checks(MYSQL* admin, const char* host, const char* port,
                          const char* user, const char* pass) {
    const std::string table = "admin_pgsql_prepared_shape_" + std::to_string(getpid());
    using duckdb_replica_test::query;
    if (!query(admin, "CREATE TABLE " + table + " (id INTEGER)") ||
        !query(admin, "INSERT INTO " + table + " VALUES (7)"))
        BAIL_OUT("cannot create the owned Admin schema fixture");
    PGconn* connection = connect_user(host, port, user, pass);
    if (!connection || PQstatus(connection) != CONNECTION_OK)
        BAIL_OUT("cannot connect the PostgreSQL Admin schema test");
    const std::string sql = "SELECT * FROM " + table;
    PGresult* result = PQprepare(connection, "before_schema_change", sql.c_str(), 0, nullptr);
    ok(PQresultStatus(result) == PGRES_COMMAND_OK, "prepare before an Admin schema change");
    PQclear(result);
    result = PQexecPrepared(connection, "before_schema_change", 0, nullptr, nullptr, nullptr, 0);
    ok(PQresultStatus(result) == PGRES_TUPLES_OK && PQnfields(result) == 1 && PQntuples(result) == 1 &&
       !std::strcmp(PQgetvalue(result, 0, 0), "7"), "prepared query reads the original Admin schema");
    PQclear(result);
    if (!query(admin, "ALTER TABLE " + table + " ADD COLUMN note TEXT DEFAULT 'fresh'"))
        BAIL_OUT("cannot alter the owned Admin schema fixture");
    result = PQexecPrepared(connection, "before_schema_change", 0, nullptr, nullptr, nullptr, 0);
    ok(state(result, "0A000") && PQtransactionStatus(connection) == PQTRANS_IDLE,
       "schema drift returns 0A000 and the connection returns to idle: %s", PQresultErrorMessage(result));
    PQclear(result);
    result = PQprepare(connection, "after_schema_change", sql.c_str(), 0, nullptr);
    ok(PQresultStatus(result) == PGRES_COMMAND_OK, "reprepare after the Admin schema change");
    PQclear(result);
    result = PQexecPrepared(connection, "after_schema_change", 0, nullptr, nullptr, nullptr, 0);
    ok(rows(result, "7", "fresh") && !std::strcmp(PQfname(result, 1), "note"),
       "reprepared query reads the updated schema and default value");
    PQclear(result);
    PQfinish(connection);
    if (!query(admin, "DROP TABLE " + table))
        BAIL_OUT("cannot remove the owned Admin schema fixture");
}

static std::string messages(PgConnection& c, std::string* sqlstate = nullptr) {
    std::string s;
    if (sqlstate)
        sqlstate->clear();
    for (const auto& m : c.readUntilQuiet(100)) {
        s += m.first;
        if (sqlstate && m.first == 'E') {
            BufferReader fields(m.second);
            while (fields.remaining()) {
                const char field = fields.readByte();
                if (!field)
                    break;
                const std::string value = fields.readString();
                if (field == 'C')
                    *sqlstate = value;
            }
        }
    }
    return s;
}

static void wire_quota_checks(PgConnection& c) {
    constexpr int handle_limit = 128;
    for (int i = 0; i < handle_limit; ++i)
        c.prepareStatement("stmt_" + std::to_string(i), "SELECT 1", false);
    c.sendSync();
    std::string seq = messages(c);
    ok(seq == std::string(handle_limit, '1') + "Z", "accept 128 named statements before Sync");
    c.prepareStatement("overflow", "SELECT 1", false);
    c.sendSync();
    std::string sqlstate;
    seq = messages(c, &sqlstate);
    ok(seq == "EZ" && sqlstate == "54000", "statement quota returns 54000 and Sync restores ReadyForQuery");
    c.closeStatement("stmt_0", false);
    c.prepareStatement("replacement", "SELECT 1", false);
    c.sendSync();
    seq = messages(c);
    ok(seq == "31Z", "closing a named statement releases quota for a replacement");

    for (int i = 0; i < handle_limit; ++i)
        c.bindStatement("replacement", "portal_" + std::to_string(i), {}, {}, false);
    c.sendFlush();
    seq = messages(c);
    ok(seq == std::string(handle_limit, '2'), "accept 128 named portals before Sync");
    c.closePortal("portal_0", false);
    c.bindStatement("replacement", "replacement_portal", {}, {}, false);
    c.sendFlush();
    seq = messages(c);
    ok(seq == "32", "closing one portal releases quota within the same cycle");
    c.bindStatement("replacement", "overflow_portal", {}, {}, false);
    c.sendSync();
    seq = messages(c, &sqlstate);
    ok(seq == "EZ" && sqlstate == "54000", "portal quota returns 54000 and Sync restores ReadyForQuery");
    c.bindStatement("replacement", "recovered_portal", {}, {}, false);
    c.executePortal("recovered_portal", 0, false);
    c.sendSync();
    seq = messages(c);
    ok(seq == "2DCZ", "Sync releases portals and preserves the named statement");
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
        c.sendQuery("SELECT 1"); seq = messages(c);
        ok(seq == "TDCZ", "legacy simple Query recovers after Sync: %s", seq.c_str());
        c.bindStatement("s", "recovered", {}, {}, false);
        c.executePortal("recovered", 0, false); c.sendSync(); seq = messages(c);
        ok(seq == "2DDCZ", "named statement remains usable after rejected Parse and Sync: %s", seq.c_str());
        c.closeStatement("s", false);
        c.sendSync();
        seq = messages(c);
        ok(seq == "3Z", "close the original named statement before checking quotas");
        wire_quota_checks(c);
    } catch (const std::exception& e) {
        diag("wire protocol test failed: %s", e.what());
        BAIL_OUT("wire protocol connection failed");
    }
}
int main(int argc, char** argv) {
    prepared_owned_fixture::Fixture fixture("native", false);
    const char* host = env("TAP_PGSQL_ADMINHOST"), *port = env("TAP_PGSQL_ADMINPORT");
    const char* user = env("TAP_PGSQL_ADMINUSERNAME"), *pass = env("TAP_PGSQL_ADMINPASSWORD");
    if (!host || !port || !user || !pass) { diag("Set TAP_PGSQL_ADMINHOST/ADMINPORT/ADMINUSERNAME/ADMINPASSWORD"); return EXIT_FAILURE; }
    const char* su = env("TAP_PGSQL_STATSUSERNAME"), *sp = env("TAP_PGSQL_STATSPASSWORD");
    if (!!su != !!sp) { diag("Set both optional stats credentials"); return EXIT_FAILURE; }
    alarm(60); // Bound connect, DNS and libpq operations as well as socket reads.
    if (argc == 2 && !strcmp(argv[1], "--expect-legacy")) {
        plan(su ? 4 : 2);
        for (const auto& credentials : {std::pair{user, pass}, std::pair{su, sp}}) {
            if (!credentials.first) continue;
            PGconn* connection = connect_user(host, port, credentials.first, credentials.second);
            if (PQstatus(connection) != CONNECTION_OK) BAIL_OUT("Admin/STATS connection failed");
            const char* value = "17";
            PGresult* result = PQexecParams(connection, "SELECT $1::int", 1, nullptr,
                                            &value, nullptr, nullptr, 0);
            ok(state(result, "0A000"), "legacy PostgreSQL Admin/STATS rejects parameterized SELECT");
            PQclear(result);
            result = PQexec(connection, "SELECT 17");
            ok(PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1 &&
               !strcmp(PQgetvalue(result, 0, 0), "17"),
               "legacy PostgreSQL Admin/STATS still accepts simple queries after Sync");
            PQclear(result);
            PQfinish(connection);
        }
        return exit_status();
    }
    constexpr int wire_count = 19;
    plan(32 + wire_count + (su ? 23 + wire_count : 0) + (fixture.admin ? 7 : 0));
    if (fixture.admin) {
        const std::string frontend_port = std::to_string(fixture.p);
        PGconn* frontend = connect_user(host, frontend_port.c_str(), "fixture_client", "fixture_client");
        ok(frontend && PQstatus(frontend) == CONNECTION_OK &&
           admin_login_denied(host, port, "fixture_client", "fixture_client"),
           "ordinary PostgreSQL credentials work on the frontend and are denied on the Admin listener");
        PQfinish(frontend);
        ok(admin_login_denied(host, port, user, "incorrect_fixture_password"),
           "PostgreSQL Admin authentication rejects an incorrect password");
        schema_checks(fixture.admin, host, port, user, pass);
    }
    libpq_checks(host, port, user, pass, false); wire_checks(host, port, user, pass);
    if (su) {
        libpq_checks(host, port, su, sp, true);
        wire_checks(host, port, su, sp);
    }
    return exit_status();
}
