#include "prepared_owned_fixture.h"
#include "libpq-fe.h"
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <unistd.h>

static bool state(PGresult *r, const char *code) {
    const char *s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
    return s && !strcmp(s, code);
}
static bool good(PGresult *r, ExecStatusType s) {
    return r && PQresultStatus(r) == s;
}
int main() {
    prepared_owned_fixture::Fixture fixture;
    plan(NO_PLAN);
    const char *host = getenv("TAP_HOST"), *port = getenv("TAP_DUCKDB_PGSQL_PORT"),
               *user = getenv("TAP_USERNAME"), *pass = getenv("TAP_PASSWORD");
    if (!user || !*user || !pass)
        BAIL_OUT("TAP_USERNAME and TAP_PASSWORD are required");
    const char *keys[] = {
        "host", "port", "user", "password", "dbname", "sslmode", "connect_timeout", nullptr};
    const char *vals[] = {host && *host ? host : "127.0.0.1",
                          port && *port ? port : "6034",
                          user,
                          pass,
                          "main",
                          "disable",
                          "3",
                          nullptr};
    PGconn *c = PQconnectdbParams(keys, vals, 0);
    if (PQstatus(c) != CONNECTION_OK)
        BAIL_OUT("connect: %s", PQerrorMessage(c));
    Oid types[] = {20, 25};
    PGresult *r = PQprepare(
        c, "bound", "SELECT CAST($1 AS BIGINT) + CAST($1 AS BIGINT), length(CAST($2 AS VARCHAR))",
        2, types);
    bool prepared = good(r, PGRES_COMMAND_OK);
    ok(prepared, "prepare typed repeated parameters: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQdescribePrepared(c, "bound");
    ok(good(r, PGRES_COMMAND_OK) && PQnparams(r) == 2 && PQparamtype(r, 0) == 20 &&
           PQparamtype(r, 1) == 25 && PQnfields(r) == 2 && PQftype(r, 0) == 20 &&
           PQftype(r, 1) == 20,
       "describe typed parameters and BIGINT outputs");
    PQclear(r);
    const char *v[] = {"21", "x'); DROP TABLE t; --"};
    r = PQexecPrepared(c, "bound", 2, v, nullptr, nullptr, 0);
    ok(prepared && good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1 &&
           !strcmp(PQgetvalue(r, 0, 0), "42") &&
           atoi(PQgetvalue(r, 0, 1)) == static_cast<int>(std::string_view(v[1]).size()),
       "execute repeated number and literal SQL-shaped text");
    PQclear(r);
    v[0] = "-3";
    v[1] = "";
    r = PQexecPrepared(c, "bound", 2, v, nullptr, nullptr, 0);
    ok(good(r, PGRES_TUPLES_OK) && !strcmp(PQgetvalue(r, 0, 0), "-6") &&
           !strcmp(PQgetvalue(r, 0, 1), "0") && !PQgetisnull(r, 0, 1),
       "rebind negative integer and empty text");
    PQclear(r);
    v[1] = nullptr;
    r = PQexecPrepared(c, "bound", 2, v, nullptr, nullptr, 0);
    ok(good(r, PGRES_TUPLES_OK) && PQgetisnull(r, 0, 1), "NULL text remains NULL");
    PQclear(r);
    std::string table = "duckdb_prep_pg_" + std::to_string((long)getpid());
    r = PQexec(
        c, ("CREATE TABLE " + table + " (v INTEGER, b BOOLEAN, f BOOLEAN, d DECIMAL(8,2), x BLOB)")
               .c_str());
    bool created = good(r, PGRES_COMMAND_OK);
    if (!created)
        BAIL_OUT("create owned table: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQexec(c,
               ("INSERT INTO " + table + " VALUES (1, TRUE, FALSE, 12.34, '\\x00\\xFF')").c_str());
    if (!good(r, PGRES_COMMAND_OK))
        BAIL_OUT("insert fixture: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQprepare(c, "constants", ("SELECT b, f, d, x FROM " + table).c_str(), 0, nullptr);
    bool constants = good(r, PGRES_COMMAND_OK);
    ok(constants, "prepare native constants: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQexecPrepared(c, "constants", 0, nullptr, nullptr, nullptr, 0);
    ok(constants && good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1 && PQftype(r, 0) == 16 &&
           PQftype(r, 1) == 16 && PQftype(r, 2) == 1700 && PQftype(r, 3) == 17 &&
           !strcmp(PQgetvalue(r, 0, 0), "t") && !strcmp(PQgetvalue(r, 0, 1), "f") &&
           !strcmp(PQgetvalue(r, 0, 2), "12.34") && !strcmp(PQgetvalue(r, 0, 3), "\\x00ff"),
       "boolean, decimal and blob values and types");
    PQclear(r);
    auto count = [&]() -> long {
        PGresult *q = PQexec(c, ("SELECT COUNT(*) FROM " + table).c_str());
        long n = good(q, PGRES_TUPLES_OK) && PQntuples(q) == 1
                     ? strtol(PQgetvalue(q, 0, 0), nullptr, 10)
                     : -1;
        PQclear(q);
        return n;
    };
    auto write = [&](const char *name, const std::string &sql, const char *value,
                     const char *affected) {
        Oid type[] = {23};
        PGresult *q = PQprepare(c, name, sql.c_str(), 1, type);
        bool success = good(q, PGRES_COMMAND_OK);
        if (!success) diag("prepare write failed: %s", PQresultErrorMessage(q));
        PQclear(q);
        if (!success) return false;
        const char *values[] = {value};
        q = PQexecPrepared(c, name, 1, values, nullptr, nullptr, 0);
        success = good(q, PGRES_COMMAND_OK) && !strcmp(PQcmdTuples(q), affected);
        if (!success) diag("execute write failed: %s", PQresultErrorMessage(q));
        PQclear(q);
        return success;
    };
    ok(write("insert_value", "INSERT INTO " + table + " (v) VALUES ($1)", "2", "1"),
       "bound INSERT reports one affected row");
    ok(count() == 2, "ordinary SELECT sees prepared INSERT");
    ok(write("update_value", "UPDATE " + table + " SET v = 5 WHERE v = $1", "2", "1"),
       "bound UPDATE reports one affected row");
    ok(write("delete_value", "DELETE FROM " + table + " WHERE v = $1", "5", "1"),
       "bound DELETE reports one affected row");
    const char *missing[] = {"5"};
    r = PQexecPrepared(c, "delete_value", 1, missing, nullptr, nullptr, 0);
    ok(good(r, PGRES_COMMAND_OK) && !strcmp(PQcmdTuples(r), "0"),
       "bound DELETE reports zero affected rows when no rows match");
    PQclear(r);
    ok(count() == 1, "ordinary SELECT sees prepared UPDATE and DELETE");
    Oid returning_type[] = {23};
    r = PQprepare(c, "insert_returning", ("INSERT INTO " + table + " (v) VALUES ($1) RETURNING v").c_str(), 1, returning_type);
    bool returning_prepared = good(r, PGRES_COMMAND_OK);
    ok(returning_prepared, "prepare bound INSERT RETURNING: %s", PQresultErrorMessage(r));
    PQclear(r);
    const char *returning_value[] = {"9"};
    r = PQexecPrepared(c, "insert_returning", 1, returning_value, nullptr, nullptr, 0);
    ok(returning_prepared && good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1 &&
           !strcmp(PQgetvalue(r, 0, 0), "9"), "bound INSERT RETURNING yields inserted value");
    PQclear(r);
    ok(count() == 2, "ordinary SELECT sees successful RETURNING write");
    r = PQexec(c, ("DELETE FROM " + table + " WHERE v = 9").c_str());
    ok(good(r, PGRES_COMMAND_OK), "remove successful RETURNING row");
    PQclear(r);
    r = PQprepare(c, "oversized_returning", ("INSERT INTO " + table + " (v) VALUES (10) RETURNING repeat('x', 67108865)").c_str(), 0, nullptr);
    bool oversized_prepared = good(r, PGRES_COMMAND_OK);
    ok(oversized_prepared, "prepare write with oversized RETURNING result: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQexecPrepared(c, "oversized_returning", 0, nullptr, nullptr, nullptr, 0);
    ok(!good(r, PGRES_TUPLES_OK) && strstr(PQresultErrorMessage(r), "budget"),
       "oversized RETURNING result is refused by the result budget: %s", PQresultErrorMessage(r));
    PQclear(r);
    ok(count() == 1, "refused oversized RETURNING rolls back write");
    r = PQprepare(c, "external",
                  "SELECT * FROM read_parquet('/tmp/duckdb_prepared_forbidden.parquet')", 0,
                  nullptr);
    ok(!good(r, PGRES_COMMAND_OK) &&
           (strstr(PQresultErrorMessage(r), "external access") ||
            strstr(PQresultErrorMessage(r), "file system operations are disabled")),
       "prepared external file access respects database policy: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQexec(c, "BEGIN");
    ok(good(r, PGRES_COMMAND_OK), "begin explicit transaction");
    PQclear(r);
    ok(write("insert_in_tx", "INSERT INTO " + table + " (v) VALUES ($1)", "3", "1"),
       "bound INSERT executes in explicit transaction");
    ok(count() == 2, "ordinary SELECT sees prepared transaction write");
    r = PQexec(c, "ROLLBACK");
    ok(good(r, PGRES_COMMAND_OK), "rollback transaction");
    PQclear(r);
    ok(count() == 1, "rollback removes prepared transaction write");
    r = PQexec(c, "SELECT 1");
    ok(good(r, PGRES_TUPLES_OK) && !strcmp(PQgetvalue(r, 0, 0), "1"),
       "session healthy after refusals");
    PQclear(r);
    const std::string wide = "duckdb_wide_pg_" + std::to_string((long)getpid());
    const char *min128 = "-170141183460469231731687303715884105728";
    const char *maxu128 = "340282366920938463463374607431768211455";
    const char *over128 = "170141183460469231731687303715884105728";
    r = PQexec(c, ("CREATE TABLE " + wide + " (w HUGEINT, u UHUGEINT)").c_str());
    bool wide_created = good(r, PGRES_COMMAND_OK);
    ok(wide_created, "create owned wide table: %s", PQresultErrorMessage(r));
    PQclear(r);
    if (wide_created) {
        std::string insert =
            "INSERT INTO " + wide + " VALUES ('" + min128 + "', '" + maxu128 + "')";
        r = PQexec(c, insert.c_str());
        ok(good(r, PGRES_COMMAND_OK), "insert wide boundaries: %s", PQresultErrorMessage(r));
        PQclear(r);
        Oid numeric[] = {1700};
        r = PQprepare(c, "wide", ("SELECT w, u FROM " + wide + " WHERE w = $1").c_str(), 1,
                      numeric);
        bool wide_prepared = good(r, PGRES_COMMAND_OK);
        ok(wide_prepared, "prepare wide predicate: %s", PQresultErrorMessage(r));
        PQclear(r);
        r = PQdescribePrepared(c, "wide");
        const int typmod = (39 << 16) + 4;
        ok(good(r, PGRES_COMMAND_OK) && PQnfields(r) == 2 && PQftype(r, 0) == 1700 &&
               PQftype(r, 1) == 1700 && PQfmod(r, 0) == typmod && PQfmod(r, 1) == typmod,
           "wide columns advertise NUMERIC(39,0)");
        PQclear(r);
        const char *wide_values[] = {min128};
        r = PQexecPrepared(c, "wide", 1, wide_values, nullptr, nullptr, 0);
        ok(wide_prepared && good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1 &&
               !strcmp(PQgetvalue(r, 0, 0), min128) && !strcmp(PQgetvalue(r, 0, 1), maxu128),
           "bind signed minimum and return exact signed and unsigned boundaries");
        PQclear(r);
        wide_values[0] = over128;
        r = PQexecPrepared(c, "wide", 1, wide_values, nullptr, nullptr, 0);
        ok(!good(r, PGRES_TUPLES_OK), "out-of-range signed HUGEINT bind is refused");
        PQclear(r);
        wide_values[0] = min128;
        r = PQexecPrepared(c, "wide", 1, wide_values, nullptr, nullptr, 0);
        ok(good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1 && !strcmp(PQgetvalue(r, 0, 0), min128),
           "valid wide bind recovers after overflow");
        PQclear(r);
        r = PQexec(c, ("DROP TABLE " + wide).c_str());
        ok(good(r, PGRES_COMMAND_OK), "drop owned wide table");
        PQclear(r);
    }
    Oid int_type[] = {23};
    r = PQprepare(c, "sum_value", ("SELECT SUM(v) FROM " + table + " WHERE v = $1").c_str(), 1,
                  int_type);
    bool sum_prepared = good(r, PGRES_COMMAND_OK);
    ok(sum_prepared, "prepare integer SUM with typed predicate: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQdescribePrepared(c, "sum_value");
    ok(good(r, PGRES_COMMAND_OK) && PQnfields(r) == 1 && PQftype(r, 0) == 1700 &&
           PQfmod(r, 0) == ((39 << 16) + 4),
       "integer SUM advertises NUMERIC(39,0)");
    PQclear(r);
    const char *sum_values[] = {"1"};
    r = PQexecPrepared(c, "sum_value", 1, sum_values, nullptr, nullptr, 0);
    ok(sum_prepared && good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1 &&
           !strcmp(PQgetvalue(r, 0, 0), "1"),
       "integer SUM returns exact decimal value");
    PQclear(r);
    if (created) {
        r = PQexec(c, ("DROP TABLE " + table).c_str());
        ok(good(r, PGRES_COMMAND_OK), "drop owned table");
        PQclear(r);
    }
    const std::string readonly_table = table + "_ro";
    if (!fixture.dir.empty()) {
        r = PQexec(c, ("CREATE TABLE " + readonly_table + " (v INTEGER)").c_str());
        bool seeded = good(r, PGRES_COMMAND_OK); PQclear(r);
        r = PQexec(c, ("INSERT INTO " + readonly_table + " VALUES (1)").c_str());
        seeded = seeded && good(r, PGRES_COMMAND_OK); PQclear(r);
        ok(seeded, "seed read-only database fixture");
        PQfinish(c); c = nullptr;
        bool reopened = seeded && fixture.reopen_read_only();
        ok(reopened, "reopen DuckDB read-only");
        if (reopened) {
            c = PQconnectdbParams(keys, vals, 0);
            bool connected_ro = PQstatus(c) == CONNECTION_OK;
            ok(connected_ro, "connect to read-only DuckDB");
            if (connected_ro) {
                r = PQexec(c, ("SELECT * FROM " + readonly_table).c_str());
                ok(good(r, PGRES_TUPLES_OK) && PQntuples(r) == 1, "ordinary read works in read-only database"); PQclear(r);
                r = PQexec(c, ("INSERT INTO " + readonly_table + " VALUES (2)").c_str());
                ok(!good(r, PGRES_COMMAND_OK), "ordinary write is refused by read-only database"); PQclear(r);
                Oid type[] = {23};
                r = PQprepare(c, "readonly_write", ("INSERT INTO " + readonly_table + " VALUES ($1)").c_str(), 1, type);
                bool denied = !good(r, PGRES_COMMAND_OK); PQclear(r);
                if (!denied) {
                    const char *value[] = {"2"};
                    r = PQexecPrepared(c, "readonly_write", 1, value, nullptr, nullptr, 0);
                    denied = !good(r, PGRES_COMMAND_OK); PQclear(r);
                }
                ok(denied, "prepared write is refused by read-only database");
            }
        }
    }
    if (c) PQfinish(c);
    return exit_status();
}
