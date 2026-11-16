#include "duckdb_prepared_policy.h"
#include "tap.h"
#include <string>
int main() {
    plan(NO_PLAN);
    const char *allowed[] = {"SELECT 1",
                             "SELECT $1 + 2",
                             "SELECT TRUE, FALSE",
                             "SELECT count(DISTINCT a) FROM t",
                             "SELECT 'delete; nextval(1)'",
                             "SELECT count(*) FROM items WHERE id = $1",
                             "SELECT lower('HI')",
                             "SELECT coalesce(NULL, abs(-2)), sum(a) FROM t",
                             "SELECT CASE WHEN a > 1 THEN upper(a) ELSE 'copy; update' END FROM t",
                             "SELECT * FROM t WHERE a IN (SELECT a FROM u)",
                             "/* leading */ SELECT 1 -- trailing\n",
                             "SELECT 1; -- comment\n",
                             "WITH x AS (SELECT 1 AS a) SELECT a FROM x",
                             "SELECT 1 UNION ALL SELECT 2",
                             "SELECT CAST($1 AS INTEGER)",
                             "SELECT a + 2 FROM t WHERE a >= $1"};
    const char *denied[] = {"",
                            "SELECT 1; SELECT 2",
                            "SELECT 1; DELETE FROM t",
                            "DELETE FROM t",
                            "SELECT ? + 2",
                            "SELECT nextval('s')",
                            "SELECT 1 OPERATOR(pg_catalog.+) 2",
                            "SELECT CAST(1 AS evil)",
                            "SELECT * FROM count(1)",
                            "SELECT * FROM read_csv('x')",
                            "SELECT pg_catalog.lower('X')",
                            "SELECT 1; /* unterminated",
                            "SELECT 1::evil",
                            "SELECT CAST(12.34 AS DECIMAL(8,2))",
                            "SELECT 1 FOR UPDATE",
                            "SELECT 1 INTO t",
                            "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x",
                            "SELECT 1 garbage garbage",
                            "SELECT 1 /* unterminated"};
    for (auto s : allowed)
        ok(embedded::duckdb_readonly_prepared_select(s, embedded::DuckDBSourceDialect::postgresql),
           "PG admits %s", s);
    for (auto s : denied)
        ok(!embedded::duckdb_readonly_prepared_select(s, embedded::DuckDBSourceDialect::postgresql),
           "PG refuses %s", s);
    const char *mysql_allowed[] = {"SELECT ? + 2", "SELECT TRUE, FALSE",
                                   "WITH x AS (SELECT 1 AS a) SELECT a FROM x"};
    const char *mysql_denied[] = {"SELECT CAST(? AS INTEGER)",
                                  "SELECT count(DISTINCT a) FROM t",
                                  "SELECT pg_catalog.lower(?)",
                                  "SELECT nextval('x')",
                                  "SELECT * FROM read_csv('x')",
                                  "SELECT 1; DELETE FROM t",
                                  "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x",
                                  "SELECT 1 INTO t",
                                  "SELECT 1 FOR UPDATE"};
    for (auto s : mysql_allowed)
        ok(embedded::duckdb_readonly_prepared_select(s, embedded::DuckDBSourceDialect::mysql),
           "MySQL admits %s", s);
    for (auto s : mysql_denied)
        ok(!embedded::duckdb_readonly_prepared_select(s, embedded::DuckDBSourceDialect::mysql),
           "MySQL refuses %s", s);
    return exit_status();
}
