#include "duckdb_mysql_select_context.h"
#include "tap.h"
#include <cstring>

static void setup_query(duckdb_connection c, const char *sql) {
    duckdb_result r{};
    const auto status = duckdb_query(c, sql, &r);
    if (status != DuckDBSuccess) {
        diag("setup query failed: %s", duckdb_result_error(&r));
        duckdb_destroy_result(&r);
        BAIL_OUT("cannot prepare resolver test fixtures");
    }
    duckdb_destroy_result(&r);
}
int main() {
    plan(NO_PLAN);
    duckdb_database db{};
    duckdb_connection c{};
    if (duckdb_open(nullptr, &db) != DuckDBSuccess)
        BAIL_OUT("cannot open DuckDB");
    if (duckdb_connect(db, &c) != DuckDBSuccess) {
        duckdb_close(&db);
        BAIL_OUT("cannot connect to DuckDB");
    }
    setup_query(c, "CREATE SCHEMA \"Odd Schema\"");
    setup_query(c, "CREATE TABLE \"Odd Schema\".\"t`x\" (\"a\"\"b\" INTEGER PRIMARY KEY, u INTEGER "
                   "UNIQUE, n INTEGER[], d DECIMAL(9,2))");
    setup_query(c,
                "CREATE TABLE \"Odd Schema\".compound (a INTEGER, b INTEGER, PRIMARY KEY (a,b))");
    setup_query(c, "CREATE VIEW \"Odd Schema\".v AS SELECT * FROM \"Odd Schema\".compound");
    setup_query(c, "CREATE TABLE type_test (a HUGEINT, b UHUGEINT, c TIMESTAMP_NS)");
    setup_query(c, "CREATE VIEW type_view AS SELECT * FROM type_test");
    DuckDBMySQLRelation r;
    for (const char *name : {"type_test", "type_view"}) {
        auto types = duckdb_mysql_select_context(c);
        const bool resolved = types.resolve_relation({"main", name}, r);
        ok(resolved && r.columns.size() == 3, "%s resolves with three columns", name);
        for (int i = 0; i < 2; ++i)
            ok(r.columns.size() > static_cast<size_t>(i) &&
                   r.columns[i].type.kind == DuckDBMySQLTypeKind::exact_decimal &&
                   r.columns[i].type.precision == 39 && r.columns[i].type.scale == 0,
               "%s column %d maps to decimal(39,0)", name, i);
        ok(r.columns.size() > 2 && r.columns[2].type.kind == DuckDBMySQLTypeKind::unknown,
           "%s nanosecond timestamp remains unknown", name);
    }
    setup_query(c, "CREATE TABLE shadowed (x INTEGER)");
    setup_query(c, "CREATE TEMP TABLE SHADOWED (y INTEGER)");
    auto shadow = duckdb_mysql_select_context(c);
    ok(!shadow.resolve_relation({"shadowed"}, r) && r.columns.empty(),
       "case-insensitive temporary shadowing rejects unqualified lookup");
    shadow = duckdb_mysql_select_context(c);
    ok(shadow.resolve_relation({"main", "shadowed"}, r) && r.columns.size() == 1 &&
           r.columns[0].canonical_name == "x",
       "qualified lookup selects main table despite temporary shadow");
    auto context = duckdb_mysql_select_context(c);
    ok(context.resolve_relation({"Odd Schema", "t`x"}, r), "quoted schema and table names resolve");
    ok(r.canonical_name.size() == 3 && r.canonical_name[1] == "Odd Schema" &&
           r.canonical_name[2] == "t`x",
       "relation names retain canonical spelling");
    ok(r.exact_name_resolution && r.columns.size() == 4 && r.columns[0].canonical_name == "a\"b",
       "column names retain embedded quotes");
    ok(r.columns.size() > 0 && r.columns[0].type.kind == DuckDBMySQLTypeKind::signed_integer,
       "integer column maps to signed integer");
    ok(r.columns.size() > 2 && r.columns[2].type.kind == DuckDBMySQLTypeKind::unknown,
       "nested column type remains unknown");
    ok(r.columns.size() > 3 && r.columns[3].type.kind == DuckDBMySQLTypeKind::exact_decimal &&
           r.columns[3].type.precision == 9 && r.columns[3].type.scale == 2,
       "decimal column retains precision and scale");
    ok(r.unique_keys.size() == 1 && r.unique_keys[0].size() == 1 && r.unique_keys[0][0] == "a\"b",
       "only non-null primary key is reported, not nullable unique key");
    ok(!context.resolve_relation({"Odd Schema", "t`x"}, r) && r.columns.empty(),
       "resolver call limit clears output");
    context = duckdb_mysql_select_context(c);
    ok(context.resolve_relation({"Odd Schema", "compound"}, r) && r.unique_keys.size() == 1 &&
           r.unique_keys[0].size() == 2,
       "composite primary key is reported completely");
    context = duckdb_mysql_select_context(c);
    ok(context.resolve_relation({"Odd Schema", "v"}, r) && r.unique_keys.empty(),
       "view resolves without inferred unique keys");
    setup_query(c, "SET schema = 'Odd Schema'");
    context = duckdb_mysql_select_context(c);
    bool resolved = context.resolve_relation({"t`x"}, r);
    ok(resolved && r.canonical_name.size() == 3, "unqualified lookup uses current schema");
    const auto catalog = r.canonical_name.empty() ? std::string() : r.canonical_name[0];
    context = duckdb_mysql_select_context(c);
    ok(context.resolve_relation({catalog, "Odd Schema", "t`x"}, r),
       "three-part native name resolves");
    context = duckdb_mysql_select_context(c);
    ok(!context.resolve_relation({"odd schema", "t`x"}, r) && r.columns.empty(),
       "non-exact schema spelling is rejected");
    context = duckdb_mysql_select_context(c);
    ok(!context.resolve_relation({"missing"}, r) && r.columns.empty(),
       "missing relation is rejected");
    DuckDBMySQLContextLimits limits;
    limits.max_columns = 2;
    context = duckdb_mysql_select_context(c, limits);
    ok(!context.resolve_relation({"t`x"}, r) && r.columns.empty(),
       "column limit rejects oversized metadata");
    limits = {};
    limits.max_metadata_bytes = 4;
    context = duckdb_mysql_select_context(c, limits);
    ok(!context.resolve_relation({"t`x"}, r) && r.columns.empty(),
       "byte limit rejects oversized metadata");
    duckdb_result failed{};
    const duckdb_state failure = duckdb_query(c, "SELECT * FROM absent_catalog_relation", &failed);
    const char *error = duckdb_result_error(&failed);
    ok(failure == DuckDBError && error && std::strstr(error, "absent_catalog_relation"),
       "missing relation query reports expected error");
    duckdb_destroy_result(&failed);
    context = duckdb_mysql_select_context(c);
    ok(context.resolve_relation({"t`x"}, r), "resolver remains usable after failed query cleanup");
    duckdb_disconnect(&c);
    duckdb_close(&db);
    return exit_status();
}
