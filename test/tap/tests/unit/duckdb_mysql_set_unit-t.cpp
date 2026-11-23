#include "duckdb_mysql_set.h"
#include "tap.h"
int main() {
    plan(NO_PLAN);
    auto parse = [](const char *s) { return duckdb_parse_mysql_set(s); };
    auto names = parse("SET NAMES utf8mb4 COLLATE utf8mb4_bin");
    ok(names.kind == DuckDBMySQLSetKind::names && names.charset == "utf8mb4" &&
           names.collation == "utf8mb4_bin",
       "parse charset and collation");
    ok(parse("SET NAMES latin1").charset == "latin1", "parse latin1");
    ok(parse("SET CHARACTER SET utf8").kind == DuckDBMySQLSetKind::charset, "parse character set");
    ok(parse("SET AUTOCOMMIT=0").kind == DuckDBMySQLSetKind::autocommit_off,
       "parse autocommit off");
    ok(parse("SET AUTOCOMMIT=1").kind == DuckDBMySQLSetKind::autocommit_on, "parse autocommit on");
    ok(parse("SET NAMES utf8mb4; SELECT 1").kind == DuckDBMySQLSetKind::other,
       "refuse multiple statements");
    ok(parse("SET NAMES utf8mb4 COLLATE").kind == DuckDBMySQLSetKind::other,
       "refuse missing collation");
    ok(parse("SET NAMES utf8mb4 trailing").kind == DuckDBMySQLSetKind::other,
       "refuse trailing input");
    ok(parse("SET AUTOCOMMIT=0, sql_mode=1").kind == DuckDBMySQLSetKind::other,
       "refuse multiple assignments");
    ok(parse("SET GLOBAL AUTOCOMMIT=1").kind == DuckDBMySQLSetKind::other,
       "refuse global assignment");
    ok(parse("SELECT 1").kind == DuckDBMySQLSetKind::other, "ignore ordinary query");
    return exit_status();
}
