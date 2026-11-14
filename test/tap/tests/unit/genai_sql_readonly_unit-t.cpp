#include "SQL_Readonly_Validator.h"
#include "PgSQL_Readonly_Transaction.h"
#include "MySQL_Query_Limit.h"
#include <stdexcept>
#include <vector>
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


struct PolicyCase { const char* sql; bool accepted; };
static const PolicyCase boundary_cases[] = {
    {R"(SELECT 'a\' INTO OUTFILE '/tmp/x' -- ')", false},
    {R"(SELECT 'a\' ' INTO newtab FROM pg_class WHERE 't' --')", false},
    {R"(SELECT 'a\_%')", false},
    {R"(SELECT "load_file"('/tmp/x'))", false},
    {R"(SELECT "sleep"(3600))", false},
    {"SELECT SLEEP(3600)", false},
    {"SELECT BENCHMARK(1000000, MD5('x'))", false},
    {"SELECT pg_sleep(3600)", false},
    {"SELECT pg_catalog.pg_sleep_for('1 hour')", false},
    {"SELECT pg_sleep_until('tomorrow')", false},
    {"EXPLAIN ANALYSE SELECT 1", false},
    {"EXPLAIN (VERBOSE, ANALYSE true) SELECT 1", false},
    {"EXPLAIN (\"analyse\") SELECT 1", false},
    {"SELECT 'sleep', 'nextval', 'load_file'", true},
    {"SELECT 'a''b', 'ordinary value'", true},
    {"SELECT 1 AS sleep, 2 AS nextval, 3 AS analyse", true},
    {"SELECT 1 AS \"pg_sleep\"", true},
};
static const char* pg_effect_functions[] = {
    "set_config", "setval", "nextval", "lo_import", "lo_export",
    "pg_advisory_lock", "pg_advisory_lock_shared", "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared", "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared", "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared", "pg_terminate_backend",
    "pg_cancel_backend", "dblink", "dblink_exec", "dblink_send_query",
    "dblink_open", "dblink_connect", "dblink_connect_u"
};
static const char* pg_unicode_cases[] = {
    R"(SELECT U&"pg\005fsleep"(1))",
    R"(SELECT U&"pg!005fsleep" UESCAPE '!' (1))",
    R"(SELECT u&"nextval"('seq'))",
    R"(SELECT U&'d!0061t' UESCAPE '!')"
};

static void test_boundaries() {
    for (bool pgsql : {false, true}) for (bool select_only : {false, true}) {
        for (const auto& c : boundary_cases) {
            const bool actual = pgsql
                ? genai::readonly_sql<sql_parser::Dialect::PostgreSQL>(c.sql, select_only)
                : genai::readonly_sql<sql_parser::Dialect::MySQL>(c.sql, select_only);
            ok(actual == c.accepted, "SQL boundary (pgsql=%d SELECT-only=%d): %s",
               pgsql, select_only, tap_sql(c.sql).c_str());
        }
    }
    for (bool select_only : {false, true}) {
        for (auto name : pg_effect_functions) {
            std::string sql = std::string("SELECT pg_catalog.\"") + name + "\"(1)";
            ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>(sql, select_only),
               "reject qualified quoted PostgreSQL effect function: %s", name);
        }
        for (auto sql : pg_unicode_cases)
            ok(!genai::readonly_sql<sql_parser::Dialect::PostgreSQL>(sql, select_only),
               "reject unsupported Unicode escape form: %s", sql);
    }
    for (auto sql : {"WITH x AS (SELECT 1) SELECT * FROM x", "EXPLAIN SELECT 1 AS analyse",
                     "SHOW TABLES", "DESC t"})
        ok(genai::readonly_sql<sql_parser::Dialect::MySQL>(sql),
           "query mode retains statement family: %s", sql);
}

struct TransactionState {
    bool idle = true, begin_ok = true, rollback_ok = true, rollback_idle = true;
    bool reusable = false;
    unsigned releases = 0;
    std::vector<std::string> events;
    bool command(const char* sql) {
        events.emplace_back(sql);
        if (events.back() == "BEGIN TRANSACTION READ ONLY") {
            if (begin_ok) idle = false;
            return begin_ok;
        }
        if (rollback_ok) idle = rollback_idle;
        return rollback_ok;
    }
    genai::PgSQL_Readonly_Transaction guard() {
        return genai::PgSQL_Readonly_Transaction(
            [&](const char* sql) { return command(sql); }, [&] { return idle; },
            [&](bool clean) { ++releases; reusable = clean; events.emplace_back(clean ? "REUSE" : "DISCARD"); });
    }
};

static void test_transaction_cleanup() {
    TransactionState success;
    {
        auto guard = success.guard();
        ok(guard.ready(), "idle connection begins a read-only transaction");
        ok(success.events == std::vector<std::string>{"BEGIN TRANSACTION READ ONLY"},
           "connection remains checked out until query completion");
        ok(guard.finish(), "successful query rolls back before reuse");
        ok(success.events == std::vector<std::string>{"BEGIN TRANSACTION READ ONLY", "ROLLBACK", "REUSE"},
           "rollback precedes returning connection to pool");
        ok(guard.finish(), "explicit cleanup is idempotent");
    }
    ok(success.releases == 1, "destructor does not release connection twice");
    for (const char* outcome : {"query error", "null query result"}) {
        TransactionState error;
        { auto guard = error.guard(); ok(guard.ready(), "%s starts guarded execution", outcome); }
        ok(error.reusable && error.idle, "%s rolls back and restores idle connection", outcome);
        ok(error.events == std::vector<std::string>{"BEGIN TRANSACTION READ ONLY", "ROLLBACK", "REUSE"},
           "%s cleans up before pool release", outcome);
    }
    TransactionState dirty;
    dirty.idle = false;
    { auto guard = dirty.guard(); ok(!guard.ready(), "preexisting transaction refuses execution"); }
    ok(dirty.events == std::vector<std::string>{"DISCARD"}, "dirty connection cannot nest BEGIN READ ONLY");
    ok(dirty.releases == 1 && !dirty.reusable, "dirty connection is removed from pool");
    TransactionState begin_error;
    begin_error.begin_ok = false;
    { auto guard = begin_error.guard(); ok(!guard.ready(), "failed BEGIN refuses query execution"); }
    ok(begin_error.events == std::vector<std::string>{"BEGIN TRANSACTION READ ONLY", "ROLLBACK", "REUSE"},
       "failed BEGIN still rolls back before release");
    ok(begin_error.reusable && begin_error.releases == 1, "failed BEGIN reuses only a reset idle connection");
    TransactionState rollback_error;
    rollback_error.rollback_ok = false;
    { auto guard = rollback_error.guard(); ok(!guard.finish(), "failed rollback fails cleanup"); }
    ok(!rollback_error.reusable, "failed rollback discards connection");
    ok(rollback_error.releases == 1, "failed rollback cannot release connection twice");
    TransactionState unknown;
    unknown.rollback_idle = false;
    { auto guard = unknown.guard(); ok(!guard.finish(), "successful rollback with non-idle state fails cleanup"); }
    ok(!unknown.reusable && unknown.releases == 1, "non-idle rollback result discards connection");
}

static void test_query_limits() {
    const struct { const char* sql; const char* expected; } cases[] = {
        {"/* LIMIT */ SELECT id FROM t", "/* LIMIT */ SELECT id FROM t LIMIT 17"},
        {"SELECT 'LIMIT ', 'COUNT(' FROM t", "SELECT 'LIMIT ', 'COUNT(' FROM t LIMIT 17"},
        {"SELECT id /* COUNT( */ FROM t", "SELECT id /* COUNT( */ FROM t LIMIT 17"},
        {"SELECT id FROM (SELECT id FROM t LIMIT 1) x", "SELECT id FROM (SELECT id FROM t LIMIT 1) x LIMIT 17"},
        {"SELECT id FROM t; -- trailing", "SELECT id FROM t LIMIT 17; -- trailing"},
        {"SELECT id FROM t # LIMIT", "SELECT id FROM t LIMIT 17 # LIMIT"},
        {"SELECT `LIMIT`, `COUNT` FROM t", "SELECT `LIMIT`, `COUNT` FROM t LIMIT 17"},
        {"SELECT id FROM t LIMIT\n3", "SELECT id FROM t LIMIT\n3"},
        {"SELECT COUNT(*) FROM t", "SELECT COUNT(*) FROM t"},
        {"SELECT id FROM t GROUP /**/ BY id", "SELECT id FROM t GROUP /**/ BY id"}
    };
    for (const auto& c : cases)
        ok(genai::MySQL_Query_Limit(c.sql).apply(c.sql, 17) == c.expected,
           "MySQL row cap uses outer SQL tokens: %s", tap_sql(c.sql).c_str());
    ok(genai::MySQL_Query_Limit("/* LIMIT */ SELECT /**/ * /**/ FROM t").select_star,
       "SELECT-star guard sees through comments");
    ok(!genai::MySQL_Query_Limit("SELECT 'SELECT * FROM t' FROM t").select_star,
       "SELECT-star text in a literal does not trigger the guard");
}

static void test_cleanup_exceptions() {
    bool released = false, reusable = true;
    {
        genai::PgSQL_Readonly_Transaction guard(
            [](const char* sql) { if (sql[0] == 'R') throw std::runtime_error("rollback"); return true; },
            [] { return true; }, [&](bool clean) { released = true; reusable = clean; });
    }
    ok(released && !reusable, "throwing rollback discards connection from destructor");
    unsigned idle_calls = 0;
    released = false;
    {
        genai::PgSQL_Readonly_Transaction guard([](const char*) { return true; },
            [&] { if (++idle_calls == 2) throw std::runtime_error("idle"); return true; },
            [&](bool clean) { released = true; reusable = clean; });
    }
    ok(released && !reusable, "throwing idle check still discards connection");
    unsigned releases = 0;
    {
        genai::PgSQL_Readonly_Transaction guard([](const char*) { return true; },
            [] { return true; }, [&](bool) { ++releases; throw std::runtime_error("release"); });
        ok(!guard.finish(), "throwing release reports failed cleanup");
        ok(!guard.finish(), "throwing release remains failed on repeated cleanup");
    }
    ok(releases == 1, "throwing release is attempted only once");
    released = false;
    bool propagated = false;
    try {
        genai::PgSQL_Readonly_Transaction guard(
            [](const char* sql) { if (sql[0] == 'R') throw std::runtime_error("rollback"); return true; },
            [] { return true; }, [&](bool clean) { released = true; reusable = clean; });
        throw std::runtime_error("query");
    } catch (const std::runtime_error& error) {
        propagated = std::string(error.what()) == "query";
    }
    ok(propagated, "cleanup preserves the original exception during unwinding");
    ok(released && !reusable, "cleanup discards connection during exception unwinding");
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
        "SELECT 1 AS added_at, 2 AS modified_at", "SELECT * FROM t LIMIT 1",
        "SELECT LAST_INSERT_ID()", "SELECT LAST_INSERT_ID /* comment */ (/**/)", "SELECT @mcp_value"
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
        "SELECT 1 /* unterminated", "SELECTED 1", "", "UPDATE t SET x=1",
        "SELECT GET_LOCK('production-job', 0)", "SELECT RELEASE_LOCK('x')",
        "SELECT RELEASE_ALL_LOCKS()", "SELECT LAST_INSERT_ID(1)",
        "SELECT SOURCE_POS_WAIT('mysql-bin.000001', 4)",
        "SELECT MASTER_POS_WAIT('mysql-bin.000001', 4)",
        "SELECT WAIT_FOR_EXECUTED_GTID_SET('3E11FA47-71CA-11E1-9E33-C80AA9429562:1')",
        "SELECT @mcp_value := 1", "SELECT @mcp_value /**/ := 1",
        "SELECT LAST_INSERT_ID /**/ (1)", "SELECT `LAST_INSERT_ID` /* x */ (1)"
    };
    plan(2 * (sizeof(allowed)/sizeof(*allowed) + sizeof(denied)/sizeof(*denied)) + 5 + 24
         + 4 * (sizeof(boundary_cases)/sizeof(*boundary_cases))
         + 2 * (sizeof(pg_effect_functions)/sizeof(*pg_effect_functions)
                + sizeof(pg_unicode_cases)/sizeof(*pg_unicode_cases)) + 4 + 23 + 10 + 12 + 7);
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
    const char* malformed_utf8[] = {
        "SELECT \x80 FROM t",
        "SELECT \xc0\xaf FROM t",
        "SELECT \xed\xa0\x80 FROM t",
        "SELECT \xf4\x90\x80\x80 FROM t",
        "SELECT a\xe2\x82 FROM t"
    };
    for (bool pgsql : {false, true})
        for (auto sql : malformed_utf8) {
            bool actual = pgsql
                ? genai::readonly_sql<sql_parser::Dialect::PostgreSQL>(sql)
                : genai::readonly_sql<sql_parser::Dialect::MySQL>(sql);
            ok(!actual, "reject malformed UTF-8 (pgsql=%d): %s", pgsql, tap_sql(sql).c_str());
        }
    test_boundaries();
    test_transaction_cleanup();
    test_query_limits();
    test_cleanup_exceptions();
    return exit_status();
}
