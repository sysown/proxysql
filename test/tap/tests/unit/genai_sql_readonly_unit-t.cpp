#include "SQL_Readonly_Validator.h"
#include "tap.h"
#include <string>

static std::string tap_sql(const char* sql) {
    std::string result;
    for (char c : std::string(sql)) {
        if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else result += c;
    }
    return result;
}

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
        "EXPLAIN/**/ANALYZE SELECT 1", "DESC ANALYZE SELECT 1",
        "DESCRIBE ANALYZE SELECT 1", "EXPLAIN (VERBOSE, ANALYZE) SELECT 1",
        "SELECT 1 /*! INTO OUTFILE '/tmp/x' */", "SELECT 1 /*M! ; DELETE FROM t */",
        "SELECT 1; --not_a_mysql_comment\nDELETE FROM t", "SELECT 'unterminated",
        "SELECT 1 /* unterminated", "SELECTED 1", "", "UPDATE t SET x=1"
    };
    plan(2 * (sizeof(allowed)/sizeof(*allowed) + sizeof(denied)/sizeof(*denied)) + 5 + 24);
    for (bool select_only : {false, true}) {
        for (auto sql : allowed)
            ok(genai::readonly_sql<sql_parser::Dialect::MySQL>(sql, select_only),
               "accept (SELECT-only=%d): %s", select_only, tap_sql(sql).c_str());
        for (auto sql : denied)
            ok(!genai::readonly_sql<sql_parser::Dialect::MySQL>(sql, select_only),
               "reject (SELECT-only=%d): %s", select_only, tap_sql(sql).c_str());
    }
    ok(genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("SELECT \"created_at\", $$DROP; UPDATE$$ FROM t"), "PostgreSQL quoting");
    ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("SELECT 1; DELETE FROM t"), "PostgreSQL chained write");
    ok(!genai::readonly_sql<sql_parser::Dialect::MySQL>("SHOW TABLES", true), "MySQL handler remains SELECT only");
    ok(genai::readonly_sql<sql_parser::Dialect::MySQL>("SHOW TABLES"), "query handler accepts SHOW");
    ok(!genai::readonly_sql<sql_parser::Dialect::MySQL>("SELECT SLEEP(1)", true), "MySQL function guard");
    for (bool pgsql : {false, true}) {
        auto check = [pgsql](const char* sql, bool expected) {
            bool actual = pgsql
                ? genai::readonly_sql<sql_parser::Dialect::PostgreSQL>(sql)
                : genai::readonly_sql<sql_parser::Dialect::MySQL>(sql);
            ok(actual == expected, "review regression (pgsql=%d): %s", pgsql, tap_sql(sql).c_str());
        };
        check("SELECT café FROM t", true);
        check("SELECT 1 AS café", true);
        check("SELECT 日本語 FROM t", true);
        check("SELECT 1 AS start", true);
        check("SELECT begin, reset FROM t", true);
        check("SELECT 1 AS analyze", true);
        check("SELECT * FROM t FOR SHARE", false);
        check("SELECT LOAD_FILE('/tmp/input')", false);
        check("SELECT 1 INTO new_table", false);
    }
    ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("EXPLAIN (\"analyze\") SELECT 1"), "quoted EXPLAIN analyze option");
    ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("EXPLAIN (VERBOSE, \"analyze\" true) SELECT 1"), "quoted EXPLAIN option after comma");
    ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("SELECT * FROM t FOR KEY SHARE"), "PostgreSQL key-share locking");
    ok(genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("EXPLAIN SELECT 1 AS \"analyze\""), "quoted alias outside EXPLAIN options");
    ok(genai::readonly_sql<sql_parser::Dialect::MySQL>("SELECT 1 AS load_file"), "LOAD_FILE alias is not function invocation");
    ok(genai::readonly_sql<sql_parser::Dialect::PostgreSQL>("SELECT share FROM t"), "SHARE identifier is not locking clause");
    return exit_status();
}
