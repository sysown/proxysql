#include "prepared_owned_fixture.h"
#include "libpq-fe.h"
#include "tap.h"
#include <cstdlib>
#include <cstring>
#include <string>
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
           !strcmp(PQgetvalue(r, 0, 0), "42") && atoi(PQgetvalue(r, 0, 1)) == (int)strlen(v[1]),
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
    r = PQprepare(c, "write", ("INSERT INTO " + table + " (v) VALUES (2)").c_str(), 0, nullptr);
    ok(!good(r, PGRES_COMMAND_OK) && state(r, "0A000") &&
           strstr(PQresultErrorMessage(r), "prepared SQL is not an allowed read-only SELECT"),
       "prepared DML refused by read-only policy: %s", PQresultErrorMessage(r));
    PQclear(r);
    ok(count() == 1, "refused DML leaves fixture unchanged");
    r = PQprepare(c, "external",
                  "SELECT * FROM read_parquet('/tmp/duckdb_prepared_forbidden.parquet')", 0,
                  nullptr);
    ok(!good(r, PGRES_COMMAND_OK) &&
           (strstr(PQresultErrorMessage(r), "prepared SQL is not an allowed read-only SELECT") ||
            strstr(PQresultErrorMessage(r), "external access")),
       "external file access refused: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQexec(c, "BEGIN");
    bool began = good(r, PGRES_COMMAND_OK);
    ok(began, "begin explicit transaction");
    PQclear(r);
    r = PQexec(c, ("INSERT INTO " + table + " (v) VALUES (3)").c_str());
    ok(good(r, PGRES_COMMAND_OK), "insert inside transaction: %s", PQresultErrorMessage(r));
    PQclear(r);
    r = PQprepare(c, "in_tx", "SELECT 1", 0, nullptr);
    ok(!good(r, PGRES_COMMAND_OK) && state(r, "25000") &&
           strstr(PQresultErrorMessage(r),
                  "prepared execution requires an idle autocommit session"),
       "prepare refused in explicit transaction: %s", PQresultErrorMessage(r));
    PQclear(r);
    ok(PQtransactionStatus(c) == PQTRANS_INTRANS || PQtransactionStatus(c) == PQTRANS_INERROR,
       "transaction remains active after refusal");
    r = PQexec(c, "ROLLBACK");
    ok(good(r, PGRES_COMMAND_OK), "rollback transaction");
    PQclear(r);
    ok(count() == 1, "rollback preserves initial row and removes transaction insert");
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
    PQfinish(c);
    return exit_status();
}
