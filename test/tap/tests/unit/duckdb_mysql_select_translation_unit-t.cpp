#include "duckdb.h"
#include "duckdb_mysql_select_compat.h"
#include "tap.h"
#include <string>
#include <vector>

int main() {
    plan(37);
    DuckDBMySQLSelectContext context;
    size_t calls = 0;
    context.resolve_relation = [&](const std::vector<std::string> &parts,
                                   DuckDBMySQLRelation &out) {
        ++calls;
        if (parts != std::vector<std::string>{"odd`table"})
            return false;
        out.canonical_name = {"odd`table"};
        out.exact_name_resolution = true;
        out.columns = {{"id", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                       {"a`b", {DuckDBMySQLTypeKind::signed_integer, 0, 0}},
                       {"txt", {DuckDBMySQLTypeKind::text, 0, 0}}};
        out.unique_keys = {{"id"}};
        return true;
    };
    auto result = duckdb_translate_mysql_select(
        "SELECT `a``b`, id AS x, id AS x FROM `odd``table` ORDER BY id LIMIT 2, 3", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported,
       "backticks and comma limit are admitted");
    ok(result.sql == "SELECT \"a`b\", \"id\" AS \"x\", \"id\" AS \"x\" FROM \"odd`table\" ORDER BY "
                     "\"id\" ASC NULLS FIRST LIMIT 3 OFFSET 2",
       "emission preserves identifiers and aliases");
    ok(calls == 1, "one metadata lookup");
    duckdb_database db = nullptr;
    duckdb_connection connection = nullptr;
    duckdb_result native{};
    bool opened = duckdb_open(nullptr, &db) == DuckDBSuccess &&
                  duckdb_connect(db, &connection) == DuckDBSuccess;
    ok(opened, "open test database");
    bool created =
        opened &&
        duckdb_query(connection,
                     "CREATE TABLE \"odd`table\" (id BIGINT, \"a`b\" BIGINT, txt VARCHAR)",
                     &native) == DuckDBSuccess;
    duckdb_destroy_result(&native);
    ok(created, "create test relation");
    duckdb_prepared_statement statement = nullptr;
    ok(created && duckdb_prepare(connection, result.sql.c_str(), &statement) == DuckDBSuccess,
       "DuckDB prepares emitted SQL");
    auto column_name = [&](idx_t index) {
        const char *name = duckdb_prepared_statement_column_name(statement, index);
        std::string value = name ? name : "";
        if (name)
            duckdb_free(const_cast<char *>(name));
        return value;
    };
    ok(statement && column_name(0) == "a`b" && column_name(1) == "x" && column_name(2) == "x",
       "DuckDB preserves duplicate result labels");
    duckdb_destroy_prepare(&statement);
    if (connection)
        duckdb_disconnect(&connection);
    if (db)
        duckdb_close(&db);
    result = duckdb_translate_mysql_select(
        "SELECT q.id FROM `odd``table` AS q ORDER BY q.id LIMIT 1", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported,
       "table alias and qualified column admitted");
    ok(result.sql.find("SELECT \"id\"") == 0, "qualified column preserves column output label");
    result = duckdb_translate_mysql_select("SELECT 001, NULL", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported, "literal SELECT admitted");
    ok(result.sql == "SELECT 001 AS \"001\", NULL AS \"NULL\"", "literal output labels preserved");
    auto refused = [&](const char *sql) {
        return duckdb_translate_mysql_select(sql, context).decision !=
               DuckDBMySQLSelectDecision::supported;
    };
    size_t before = calls;
    ok(refused("SELECT nextval('x')"), "side-effect function refused");
    ok(calls == before, "function analysis invokes no resolver or execution");
    ok(refused("SELECT @x"), "user variable refused");
    ok(refused("SELECT @@version"), "system variable refused");
    ok(refused("SELECT 1;;"), "extra empty statement refused");
    ok(refused("SELECT 1; SELECT 2"), "multiple statements refused");
    ok(refused("SELECT 1 /*! + 1 */"), "executable comment refused");
    ok(duckdb_translate_mysql_select("SELECT COUNT(*) FROM `odd``table`", context).decision ==
           DuckDBMySQLSelectDecision::supported,
       "count star admitted");
    ok(refused("SELECT COUNT(*), id FROM `odd``table`"),
       "mixed aggregate and plain columns refused");
    ok(refused("SELECT 1 + 2"), "arithmetic refused");
    ok(refused("SELECT 9223372036854775808"), "overflow literal refused");
    ok(refused("SELECT id FROM `odd``table` LIMIT 1"), "unordered limit refused");
    ok(refused("SELECT id FROM `odd``table` ORDER BY txt"),
       "text ordering refused without collation");
    ok(refused("SELECT id FROM `odd``table` WHERE txt = 'x'"), "text comparison refused");
    result = duckdb_translate_mysql_select(
        "SELECT id FROM `odd``table` WHERE id = 2 ORDER BY id DESC LIMIT 1", context);
    ok(result.decision == DuckDBMySQLSelectDecision::supported &&
           result.sql.find("DESC NULLS LAST") != std::string::npos,
       "integer comparison and MySQL null ordering admitted");
    auto bounded = context;
    bounded.max_nodes = 2;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "node bound enforced");
    bounded = context;
    bounded.max_input_bytes = 3;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "input bound enforced");
    bounded = context;
    bounded.max_output_bytes = 2;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "output bound enforced");
    ok(refused("SELECT `a``b` AS id FROM `odd``table` ORDER BY id"),
       "ambiguous ORDER BY alias refused");
    ok(refused("SELECT id AS \"x\" FROM `odd``table`"),
       "double-quoted alias refused with unknown mode");
    auto unknown = context;
    unknown.resolve_relation = [](const std::vector<std::string> &, DuckDBMySQLRelation &out) {
        out.canonical_name = {"t"};
        out.exact_name_resolution = true;
        out.columns = {{"x", {DuckDBMySQLTypeKind::unknown, 0, 0}}};
        return true;
    };
    ok(duckdb_translate_mysql_select("SELECT x FROM t", unknown).decision ==
           DuckDBMySQLSelectDecision::unsupported,
       "unknown projection type refused");
    ok(duckdb_translate_mysql_select("SELECT * FROM t", unknown).decision ==
           DuckDBMySQLSelectDecision::unsupported,
       "star with unknown type refused");
    unknown.resolve_relation = [](const std::vector<std::string> &, DuckDBMySQLRelation &) -> bool {
        throw 1;
    };
    ok(duckdb_translate_mysql_select("SELECT x FROM t", unknown).reason == "provider_failure",
       "resolver exception is contained");
    bounded = context;
    bounded.max_input_bytes = 999999;
    ok(duckdb_translate_mysql_select(std::string(65537, 'x'), bounded).reason == "resource_limit",
       "implementation hard input cap cannot be raised");
    bounded = context;
    bounded.max_depth = 1;
    ok(duckdb_translate_mysql_select("SELECT 1", bounded).reason == "resource_limit",
       "AST depth bound enforced");
    bounded = context;
    bounded.max_resolver_calls = 0;
    ok(duckdb_translate_mysql_select("SELECT id FROM `odd``table`", bounded).reason ==
           "missing_context",
       "resolver bound enforced");
    return exit_status();
}
