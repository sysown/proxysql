#include "prepared_owned_fixture.h"
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

using Messages = std::vector<std::pair<char, std::vector<uint8_t>>>;
static std::string sequence(const Messages &messages) {
    std::string result;
    for (const auto &message : messages)
        result += message.first;
    return result;
}
static bool error_state(const Messages &messages, const char *code) {
    for (const auto &message : messages) {
        if (message.first != 'E')
            continue;
        BufferReader reader(message.second);
        while (reader.remaining()) {
            char field = reader.readByte();
            if (!field)
                break;
            std::string value = reader.readString();
            if (field == 'C' && value == code)
                return true;
        }
    }
    return false;
}
static std::vector<std::vector<uint8_t>> row(const Messages &messages) {
    for (const auto &message : messages) {
        if (message.first != 'D')
            continue;
        BufferReader reader(message.second);
        int columns = reader.readInt16();
        std::vector<std::vector<uint8_t>> values;
        for (int i = 0; i < columns; ++i) {
            int length = reader.readInt32();
            if (length < 0)
                return {};
            values.push_back(reader.readBytes(length));
        }
        return values;
    }
    return {};
}
int main() {
    prepared_owned_fixture::Fixture fixture;
    alarm(60);
    plan(NO_PLAN);
    const char *host = getenv("TAP_HOST"), *port = getenv("TAP_DUCKDB_PGSQL_PORT");
    const char *user = getenv("TAP_USERNAME"), *pass = getenv("TAP_PASSWORD");
    if (!user || !*user || !pass)
        BAIL_OUT("TAP_USERNAME and TAP_PASSWORD are required");
    host = host && *host ? host : "127.0.0.1";
    port = port && *port ? port : "6034";
    const char *keys[] = {
        "host", "port", "user", "password", "dbname", "sslmode", "connect_timeout", nullptr};
    const char *values[] = {host, port, user, pass, "main", "disable", "3", nullptr};
    PGconn *setup = PQconnectdbParams(keys, values, 0);
    if (PQstatus(setup) != CONNECTION_OK)
        BAIL_OUT("setup connection: %s", PQerrorMessage(setup));
    const std::string table = "duckdb_extended_" + std::to_string((long)getpid());
    PGresult *r = PQexec(setup, ("CREATE TABLE " + table +
                                 " (v BIGINT, b BOOLEAN, x BLOB, t VARCHAR, n DECIMAL(8,2))")
                                    .c_str());
    if (PQresultStatus(r) != PGRES_COMMAND_OK)
        BAIL_OUT("create fixture: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQexec(
        setup,
        ("INSERT INTO " + table +
         " VALUES (42, TRUE, '\\x00\\xFF', 'abc', 12.34), (43, FALSE, '\\x01', 'def', 56.78)")
            .c_str());
    if (PQresultStatus(r) != PGRES_COMMAND_OK)
        BAIL_OUT("insert fixture: %s", PQresultErrorMessage(r));
    PQclear(r);
    try {
        PgConnection c(2000);
        c.connect(host, atoi(port), "main", user, pass);
        c.prepareStatement("s", "SELECT v FROM " + table + " ORDER BY v", false);
        c.describeStatement("s", false);
        c.sendSync();
        Messages m = c.readUntilQuiet(100);
        std::string seq = sequence(m);
        ok(seq == "1tTZ", "named parse and describe before execution: %s", seq.c_str());
        c.bindStatement("s", "p1", {}, {}, false);
        c.bindStatement("s", "p2", {}, {}, false);
        c.executePortal("p1", 1, false);
        c.sendFlush();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "22Ds" && row(m) == std::vector<std::vector<uint8_t>>{{'4', '2'}},
           "first portal suspends on first row: %s", seq.c_str());
        c.executePortal("p2", 1, false);
        c.sendFlush();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "Ds" && row(m) == std::vector<std::vector<uint8_t>>{{'4', '2'}},
           "second portal independently starts at first row: %s", seq.c_str());
        c.executePortal("p1", 0, false);
        c.sendFlush();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "DC" && row(m) == std::vector<std::vector<uint8_t>>{{'4', '3'}},
           "first portal resumes and completes: %s", seq.c_str());
        c.executePortal("p2", 0, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "DCZ" && row(m) == std::vector<std::vector<uint8_t>>{{'4', '3'}},
           "second portal resumes and Sync completes: %s", seq.c_str());
        c.executePortal("p2", 0, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "EZ", "Sync closes implicit portals: %s", seq.c_str());
        c.prepareStatement("", "SELECT v FROM " + table + " WHERE v = $1", false, {20});
        c.bindStatement("", "", {{{std::string("42")}, 0}}, {}, false);
        c.describePortal("", false);
        c.executePortal("", 0, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "12TDCZ" && row(m) == std::vector<std::vector<uint8_t>>{{'4', '2'}},
           "unnamed statement and portal execute: %s", seq.c_str());
        c.prepareStatement("binary",
                           "SELECT v, b, x, t FROM " + table +
                               " WHERE v = $1 AND b = $2 AND x = $3 AND t = $4",
                           false, {20, 16, 17, 25});
        std::vector<PgConnection::Param> params = {
            {{std::vector<uint8_t>{0, 0, 0, 0, 0, 0, 0, 42}}, 1},
            {{std::vector<uint8_t>{1}}, 1},
            {{std::vector<uint8_t>{0, 255}}, 1},
            {{std::vector<uint8_t>{'a', 'b', 'c'}}, 1}};
        c.bindStatement("binary", "binary_portal", params, {1}, false);
        c.describePortal("binary_portal", false);
        c.executePortal("binary_portal", 0, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "12TDCZ" && row(m) ==
                                  std::vector<std::vector<uint8_t>>{
                                      {0, 0, 0, 0, 0, 0, 0, 42}, {1}, {0, 255}, {'a', 'b', 'c'}},
           "binary int8, bool, bytea and text parameters and results: %s", seq.c_str());
        c.prepareStatement("numeric", "SELECT n FROM " + table + " WHERE v = 42", false);
        c.bindStatement("numeric", "numeric_portal", {}, {1}, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "1EZ" && error_state(m, "0A000"), "binary NUMERIC rejected with 0A000: %s",
           seq.c_str());
        c.bindStatementEx("binary", "bad", params, {0, 1}, {}, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "EZ" && error_state(m, "08P01"), "malformed Bind format count rejected: %s",
           seq.c_str());
        c.prepareStatement("schema", "SELECT * FROM " + table, false);
        c.describeStatement("schema", false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "1tTZ", "prepare and describe statement before schema change: %s", seq.c_str());
        r = PQexec(setup, ("ALTER TABLE " + table + " ADD COLUMN added INTEGER DEFAULT 9").c_str());
        ok(PQresultStatus(r) == PGRES_COMMAND_OK, "alter fixture from another connection: %s",
           PQresultErrorMessage(r));
        PQclear(r);
        c.bindStatement("schema", "old_schema", {}, {}, false);
        c.executePortal("old_schema", 0, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        bool one_error = 0;
        int errors = 0;
        bool stale_row = false;
        bool idle = false;
        for (const auto &message : m) {
            if (message.first == 'E')
                ++errors;
            if (message.first == 'D')
                stale_row = true;
            if (message.first == 'Z' && message.second.size() == 1 && message.second[0] == 'I')
                idle = true;
        }
        one_error = errors == 1 && error_state(m, "0A000");
        ok(one_error && !stale_row && idle,
           "schema change returns 0A000 before stale rows and Sync is idle: %s", seq.c_str());
        c.closeStatement("schema", false);
        c.prepareStatement("schema_new", "SELECT * FROM " + table, false);
        c.describeStatement("schema_new", false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        bool six_columns = false;
        for (const auto &message : m)
            if (message.first == 'T') {
                BufferReader reader(message.second);
                six_columns = reader.readInt16() == 6;
            }
        ok(seq == "31tTZ" && six_columns, "reprepare describes all six columns: %s", seq.c_str());
        c.bindStatement("schema_new", "new_schema", {}, {}, false);
        c.executePortal("new_schema", 0, false);
        c.sendSync();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        auto changed_row = row(m);
        ok(seq == "2DDCZ" && changed_row.size() == 6 && changed_row[5] == std::vector<uint8_t>{'9'},
           "reprepared statement executes with new column: %s", seq.c_str());
        c.bindStatement("s", "recovered", {}, {}, false);
        c.executePortal("recovered", 1, false);
        c.sendFlush();
        m = c.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "2Ds", "Sync recovers after bind errors: %s", seq.c_str());
        c.disconnect();
        PgConnection next(2000);
        next.connect(host, atoi(port), "main", user, pass);
        next.prepareStatement("after_disconnect", "SELECT v FROM " + table + " WHERE v = 42",
                              false);
        next.bindStatement("after_disconnect", "", {}, {}, false);
        next.executePortal("", 0, false);
        next.sendSync();
        m = next.readUntilQuiet(100);
        seq = sequence(m);
        ok(seq == "12DCZ" && row(m) == std::vector<std::vector<uint8_t>>{{'4', '2'}},
           "new connection works after disconnect with live portal: %s", seq.c_str());
    } catch (const std::exception &e) {
        diag("extended wire client: %s", e.what());
        r = PQexec(setup, ("DROP TABLE " + table).c_str());
        PQclear(r);
        PQfinish(setup);
        BAIL_OUT("extended wire client failed");
    }
    r = PQexec(setup, ("DROP TABLE " + table).c_str());
    ok(PQresultStatus(r) == PGRES_COMMAND_OK, "drop owned table: %s", PQresultErrorMessage(r));
    PQclear(r);
    PQfinish(setup);
    return exit_status();
}
