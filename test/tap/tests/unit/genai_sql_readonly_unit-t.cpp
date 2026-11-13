#include "SQL_Readonly_Validator.h"
#include "tap.h"
#include <string>

int main() {
    const char* allowed[] = {
        "SELECT date_created FROM t LIMIT 1", "SELECT date_updated FROM t LIMIT 1",
        "SELECT `date_created` FROM t LIMIT 1", "SELECT 1 AS created_at",
        "SELECT 1 AS xcreate", "SELECT 1 AS xstart", "SELECT 1 AS restarted",
        "SELECT visit_start_date FROM t ORDER BY date_updated LIMIT 1",
        "SELECT 'DROP TABLE t; CREATE USER x'", "SELECT 'a;b'",
        "SELECT 1 /* UPDATE t */; -- trailing comment\n",
        "SELECT 1 AS `DROP`", "SELECT '/*! DROP TABLE t */'",
        "SELECT 1 # update\n", "SELECT 1; # trailing comment\n",
        "SELECT 1 AS added_at, 2 AS modified_at", "SELECT * FROM t LIMIT 1"
    };
    const char* denied[] = {
        "SELECT 1; DELETE FROM t", "SELECT 1; RENAME TABLE t TO x",
        "SELECT 1; 'x'", "SELECT 1; `x`", "SELECT 1;;",
        "SELECT 1 INTO OUTFILE '/tmp/x'", "SELECT 1 INTO/**/DUMPFILE '/tmp/x'",
        "SELECT * FROM t FOR UPDATE", "SELECT * FROM t LOCK IN SHARE MODE",
        "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x",
        "EXPLAIN/**/ANALYZE SELECT 1", "EXPLAIN (VERBOSE, ANALYZE) SELECT 1",
        "SELECT 1 /*! INTO OUTFILE '/tmp/x' */", "SELECT 1 /*M! ; DELETE FROM t */",
        "SELECT 1; --not_a_mysql_comment\nDELETE FROM t", "SELECT 'unterminated",
        "SELECT 1 /* unterminated", "SELECTED 1", "", "UPDATE t SET x=1"
    };
    plan(2 * (sizeof(allowed)/sizeof(*allowed) + sizeof(denied)/sizeof(*denied)) + 5);
    for (bool select_only : {false, true}) {
        for (auto sql : allowed)
            ok(genai::readonly_sql<sql_parser::Dialect::MySQL>(sql, select_only),
               "accept (SELECT-only=%d): %s", select_only, sql);
        for (auto sql : denied)
            ok(!genai::readonly_sql<sql_parser::Dialect::MySQL>(sql, select_only),
               "reject (SELECT-only=%d): %s", select_only, sql);
    }
    ok(genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("SELECT \"created_at\", $$DROP; UPDATE$$ FROM t"), "PostgreSQL quoting");
    ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("SELECT 1; DELETE FROM t"), "PostgreSQL chained write");
    ok(!genai::readonly_sql<sql_parser::Dialect::MySQL>("SHOW TABLES", true), "MySQL handler remains SELECT only");
    ok(genai::readonly_sql<sql_parser::Dialect::MySQL>("SHOW TABLES"), "query handler accepts SHOW");
    ok(!genai::readonly_sql<sql_parser::Dialect::MySQL>("SELECT SLEEP(1)", true), "MySQL function guard");
    return exit_status();
}
