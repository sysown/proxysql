#include "libpq-fe.h"
#include "prepared_owned_fixture.h"
#include "tap.h"
#include <cstring>
#include <string>

static bool pg_exec(PGconn *c, const char *sql) {
    PGresult *r = PQexec(c, sql);
    bool success =
        r && (PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK);
    if (!success)
        diag("PostgreSQL %s: %s", sql, r ? PQresultErrorMessage(r) : PQerrorMessage(c));
    if (r)
        PQclear(r);
    return success;
}
static MYSQL_STMT *prepare(MYSQL *c, const char *sql) {
    MYSQL_STMT *stmt = mysql_stmt_init(c);
    if (!stmt)
        return nullptr;
    if (mysql_stmt_prepare(stmt, sql, std::strlen(sql))) {
        diag("prepare %s: %s", sql, mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return nullptr;
    }
    return stmt;
}
static bool prepared_rows(MYSQL_STMT *stmt) {
    long long id = 0;
    MYSQL_BIND bind[1]{};
    bind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    bind[0].buffer = &id;
    if (mysql_stmt_bind_result(stmt, bind) || mysql_stmt_execute(stmt))
        return false;
    bool good = !mysql_stmt_fetch(stmt) && id == 2 && !mysql_stmt_fetch(stmt) && id == 3 &&
                mysql_stmt_fetch(stmt) == MYSQL_NO_DATA;
    mysql_stmt_free_result(stmt);
    return good;
}
static bool query_rows(MYSQL *c, const char *sql) {
    if (mysql_query(c, sql)) {
        diag("query %s: %s", sql, mysql_error(c));
        return false;
    }
    MYSQL_RES *r = mysql_store_result(c);
    if (!r)
        return false;
    MYSQL_ROW first = mysql_fetch_row(r);
    bool good = first && first[0] && !std::strcmp(first[0], "2");
    MYSQL_ROW second = mysql_fetch_row(r);
    good = good && second && second[0] && !std::strcmp(second[0], "3") && !mysql_fetch_row(r);
    mysql_free_result(r);
    return good;
}
int main() {
    plan(NO_PLAN);
    prepared_owned_fixture::Fixture fixture("mysql_analytical");
    const std::string pgport = std::to_string(fixture.dp);
    const char *keys[] = {"host", "port", "user", "password", "dbname", "sslmode", nullptr};
    const char *values[] = {"127.0.0.1", pgport.c_str(), "fixture_client", "fixture_client",
                            "main",      "disable",      nullptr};
    PGconn *pg = PQconnectdbParams(keys, values, 0);
    if (!pg || PQstatus(pg) != CONNECTION_OK)
        BAIL_OUT("PostgreSQL fixture connect failed: %s",
                 pg ? PQerrorMessage(pg) : "allocation failed");
    if (!pg_exec(pg, "CREATE TABLE analytical_fixture (id INTEGER PRIMARY KEY, n INTEGER)") ||
        !pg_exec(pg, "INSERT INTO analytical_fixture VALUES (1,NULL),(2,10),(3,20)") ||
        !pg_exec(pg, "CREATE SEQUENCE analytical_sequence START 1") ||
        !pg_exec(
            pg,
            "CREATE VIEW analytical_side_effect AS SELECT nextval('analytical_sequence') AS id"))
        BAIL_OUT("PostgreSQL fixture setup failed");
    ok(true, "native PostgreSQL listener creates tables, data, sequence and view");
    MYSQL *mysql =
        duckdb_replica_test::connect("127.0.0.1", fixture.d, "fixture_client", "fixture_client");
    if (!mysql)
        BAIL_OUT("MySQL DuckDB fixture connect failed");
    ok(!mysql_set_character_set(mysql, "utf8mb4", 45), "select UTF-8 MySQL connection");
    const char *sql = "SELECT `id` FROM `analytical_fixture` ORDER BY `n`, `id` LIMIT 1,2";
    ok(query_rows(mysql, sql), "COM_QUERY translates backticks, NULL ordering and comma LIMIT");
    MYSQL_RES *r = nullptr;
    bool aliases = !mysql_query(
        mysql,
        "SELECT f.`id` AS x, f.`id` AS x FROM `analytical_fixture` AS f ORDER BY f.`id` LIMIT 1");
    if (aliases)
        r = mysql_store_result(mysql);
    MYSQL_FIELD *fields = r ? mysql_fetch_fields(r) : nullptr;
    MYSQL_ROW row = r ? mysql_fetch_row(r) : nullptr;
    ok(r && fields && mysql_num_fields(r) == 2 && !std::strcmp(fields[0].name, "x") &&
           !std::strcmp(fields[1].name, "x") && row && !std::strcmp(row[0], "1") &&
           !std::strcmp(row[1], "1"),
       "table and duplicate projection aliases survive translation");
    if (r)
        mysql_free_result(r);
    bool counted = !mysql_query(mysql, "SELECT COUNT(*) FROM `analytical_fixture`");
    r = counted ? mysql_store_result(mysql) : nullptr;
    row = r ? mysql_fetch_row(r) : nullptr;
    ok(row && row[0] && !std::strcmp(row[0], "3"), "COUNT(*) returns seeded row count");
    if (r)
        mysql_free_result(r);
    for (const char *bad :
         {"INSERT INTO analytical_fixture VALUES (4,40)", "SELECT AVG(n) FROM analytical_fixture",
          "SELECT ABS(id) FROM analytical_fixture",
          "SELECT id FROM analytical_fixture /* comment */", "SELECT ? FROM analytical_fixture"}) {
        const int query_status = mysql_query(mysql, bad);
        ok(query_status != 0 && mysql_errno(mysql) == 1235 &&
               !std::strcmp(mysql_sqlstate(mysql), "0A000"),
           "unsupported COM_QUERY returns 1235/0A000: %s (got %u/%s %s)", bad, mysql_errno(mysql),
           mysql_sqlstate(mysql), mysql_error(mysql));
    }
    const int invalid_status = mysql_query(mysql, "SELECT");
    ok(invalid_status != 0 && mysql_errno(mysql) == 1064 &&
           !std::strcmp(mysql_sqlstate(mysql), "42000"),
       "invalid SELECT returns syntax error 1064/42000 (got %u/%s %s)", mysql_errno(mysql),
       mysql_sqlstate(mysql), mysql_error(mysql));
    PGresult *pgrows = PQexec(pg, "SELECT COUNT(*) FROM analytical_fixture");
    ok(pgrows && PQresultStatus(pgrows) == PGRES_TUPLES_OK &&
           !std::strcmp(PQgetvalue(pgrows, 0, 0), "3"),
       "rejected DML leaves native data unchanged");
    if (pgrows)
        PQclear(pgrows);
    MYSQL_STMT *stmt = prepare(mysql, sql);
    ok(stmt != nullptr, "prepare translated zero-parameter SELECT");
    if (stmt) {
        ok(prepared_rows(stmt), "execute and fetch translated SELECT");
        ok(prepared_rows(stmt), "repeat translated prepared execution");
        ok(!mysql_stmt_reset(stmt), "reset translated prepared statement");
        ok(prepared_rows(stmt), "execute translated SELECT after reset");
        ok(!mysql_stmt_close(stmt), "close translated prepared statement");
    }
    stmt = prepare(mysql, "SELECT ? FROM analytical_fixture");
    ok(!stmt, "parameterized SELECT is refused");
    if (stmt)
        mysql_stmt_close(stmt);
    stmt = prepare(mysql, "SELECT COUNT(*) FROM analytical_fixture WHERE n > 1");
    ok(stmt != nullptr, "prepare COUNT with referenced integer column");
    bool changed = pg_exec(pg, "ALTER TABLE analytical_fixture ALTER COLUMN n TYPE VARCHAR");
    ok(changed, "native PostgreSQL changes referenced column type");
    if (stmt) {
        const int status = mysql_stmt_execute(stmt);
        ok(changed && status != 0 && mysql_stmt_errno(stmt) == 1615,
           "unchanged COUNT output still requires reprepare after referenced type change: %u %s",
           mysql_stmt_errno(stmt), mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
    }
    bool restored = pg_exec(pg, "ALTER TABLE analytical_fixture ALTER COLUMN n TYPE INTEGER");
    ok(restored, "native PostgreSQL restores integer column type");
    stmt =
        restored ? prepare(mysql, "SELECT COUNT(*) FROM analytical_fixture WHERE n > 1") : nullptr;
    ok(stmt != nullptr, "prepare COUNT again after restoring column type");
    if (stmt) {
        long long count = 0;
        MYSQL_BIND binding[1]{};
        binding[0].buffer_type = MYSQL_TYPE_LONGLONG;
        binding[0].buffer = &count;
        bool executed = !mysql_stmt_bind_result(stmt, binding) && !mysql_stmt_execute(stmt) &&
                        !mysql_stmt_fetch(stmt) && count == 2;
        ok(executed, "new COUNT statement executes after restoring column type");
        mysql_stmt_close(stmt);
    }
    ok(mysql_query(mysql, "SELECT id FROM analytical_side_effect") != 0,
       "COM_QUERY refuses hidden side-effect view");
    stmt = prepare(mysql, "SELECT id FROM analytical_side_effect");
    bool view_refused = !stmt || mysql_stmt_execute(stmt) != 0;
    ok(view_refused, "prepared SELECT refuses hidden side-effect view");
    if (stmt)
        mysql_stmt_close(stmt);
    pgrows = PQexec(pg, "SELECT nextval('analytical_sequence')");
    ok(pgrows && PQresultStatus(pgrows) == PGRES_TUPLES_OK &&
           !std::strcmp(PQgetvalue(pgrows, 0, 0), "1"),
       "refused view paths do not advance sequence");
    if (pgrows)
        PQclear(pgrows);
    ok(query_rows(mysql, sql), "connection recovers after rejected view");
    ok(!mysql_set_character_set(mysql, "latin1", 8), "switch client to latin1");
    ok(mysql_query(mysql, sql) != 0, "analytical query rejects latin1");
    stmt = prepare(mysql, "SELECT 1");
    ok(!stmt, "zero-parameter SELECT prepare rejects latin1");
    if (stmt)
        mysql_stmt_close(stmt);
    ok(!mysql_set_character_set(mysql, "utf8mb4", 45), "restore UTF-8 client charset");
    stmt = prepare(mysql, sql);
    ok(stmt != nullptr, "SELECT prepare recovers after restoring UTF-8");
    if (stmt) {
        ok(prepared_rows(stmt), "prepared SELECT executes after UTF-8 recovery");
        mysql_stmt_close(stmt);
    }
    ok(query_rows(mysql, sql), "analytical query recovers after restoring UTF-8");
    const std::string server =
        "INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES (91,'127.0.0.1'," +
        std::to_string(fixture.d) + ")";
    bool routed =
        duckdb_replica_test::query(fixture.admin, server) &&
        duckdb_replica_test::query(
            fixture.admin,
            "INSERT INTO mysql_query_rules(rule_id,active,username,destination_hostgroup,apply) "
            "VALUES (91,1,'fixture_client',91,1)") &&
        duckdb_replica_test::query(fixture.admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
        duckdb_replica_test::query(fixture.admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
    ok(routed, "configure query rule to the owned DuckDB listener");
    MYSQL *proxied = routed ? duckdb_replica_test::connect("127.0.0.1", fixture.m, "fixture_client",
                                                           "fixture_client")
                            : nullptr;
    ok(proxied != nullptr, "connect through ordinary MySQL listener");
    if (proxied) {
        ok(!mysql_set_character_set(proxied, "utf8mb4", 45),
           "select UTF-8 through ordinary listener");
        ok(query_rows(proxied, sql), "ordinary listener routes analytical COM_QUERY to DuckDB");
        stmt = prepare(proxied, sql);
        ok(stmt != nullptr, "ordinary listener routes analytical prepare to DuckDB");
        if (stmt) {
            ok(prepared_rows(stmt), "ordinary listener fetches translated prepared result");
            mysql_stmt_close(stmt);
        }
        mysql_close(proxied);
    }
    mysql_close(mysql);
    PQfinish(pg);
    return exit_status();
}
