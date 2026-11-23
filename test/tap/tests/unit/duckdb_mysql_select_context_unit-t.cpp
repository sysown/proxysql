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
    DuckDBMySQLContextLimits one_call;
    one_call.max_resolver_calls = 1;
    auto limited_context = duckdb_mysql_select_context(c, one_call);
    ok(limited_context.resolve_relation({"Odd Schema", "t`x"}, r),
       "explicit resolver allowance admits one call");
    ok(!limited_context.resolve_relation({"Odd Schema", "compound"}, r) && r.columns.empty(),
       "resolver call limit clears output");
    auto three_calls = duckdb_mysql_select_context(c);
    ok(three_calls.resolve_relation({"Odd Schema", "t`x"}, r) &&
           three_calls.resolve_relation({"Odd Schema", "compound"}, r) &&
           three_calls.resolve_relation({"Odd Schema", "v"}, r),
       "default resolver allowance covers three joined relations");
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
    // Source provenance recorded by the replica in proxysql_replica.columns.
    context = duckdb_mysql_select_context(c);
    ok(context.resolve_relation({"Odd Schema", "compound"}, r) && !r.columns[0].source.known(),
       "native table without replica tables has unknown source facts");
    setup_query(c, "CREATE SCHEMA shop");
    setup_query(c, "CREATE TABLE shop.sales (id BIGINT PRIMARY KEY, created TIMESTAMP, "
                   "updated TIMESTAMP, day DATE, note VARCHAR, amt DECIMAL(10,2))");
    setup_query(c, "CREATE TABLE shop.native_only (id BIGINT PRIMARY KEY, created TIMESTAMP)");
    setup_query(c, "CREATE VIEW shop.sales_view AS SELECT * FROM shop.sales");
    setup_query(c, "CREATE SCHEMA proxysql_replica");
    setup_query(c, "CREATE TABLE proxysql_replica.tables (source_id VARCHAR, schema_name VARCHAR, "
                   "table_name VARCHAR, primary_key VARCHAR, "
                   "PRIMARY KEY (source_id, schema_name, table_name))");
    setup_query(c, "INSERT INTO proxysql_replica.tables VALUES ('s1','shop','sales','id')");
    auto source_of = [&](const char *table, const char *column) {
        DuckDBMySQLRelation relation;
        auto fresh = duckdb_mysql_select_context(c);
        if (!fresh.resolve_relation({"shop", table}, relation))
            return DuckDBMySQLColumnSource{DuckDBMySQLSourceType::other, "resolve failed", ""};
        for (const auto &col : relation.columns)
            if (col.canonical_name == column)
                return col.source;
        return DuckDBMySQLColumnSource{DuckDBMySQLSourceType::other, "no column", ""};
    };
    ok(!source_of("sales", "created").known(), "manifest without a columns table stays unknown");
    setup_query(c, "CREATE TABLE proxysql_replica.\"columns\" (source_id VARCHAR, schema_name "
                   "VARCHAR, table_name VARCHAR, column_name VARCHAR, ordinal INTEGER, "
                   "mysql_data_type VARCHAR, mysql_column_type VARCHAR, character_set_name "
                   "VARCHAR, collation_name VARCHAR, duckdb_type VARCHAR, "
                   "PRIMARY KEY (source_id, schema_name, table_name, column_name))");
    setup_query(c, "INSERT INTO proxysql_replica.\"columns\" VALUES "
                   "('s1','shop','sales','id',1,'bigint','bigint(20)','','','BIGINT'),"
                   "('s1','shop','sales','created',2,'datetime','datetime(6)','','','TIMESTAMP'),"
                   "('s1','shop','sales','updated',3,'timestamp','timestamp','','','TIMESTAMP'),"
                   "('s1','shop','sales','day',4,'date','date','','','DATE'),"
                   "('s1','shop','sales','note',5,'varchar','varchar(20)','utf8mb4',"
                   "'utf8mb4_0900_bin','VARCHAR'),"
                   "('s1','shop','sales','amt',6,'decimal','decimal(10,2)','','','DECIMAL(10,2)'),"
                   "('s1','shop','native_only','id',1,'bigint','bigint(20)','','','BIGINT'),"
                   "('s1','shop','native_only','created',2,'datetime','datetime','','',"
                   "'TIMESTAMP')");
    ok(source_of("sales", "created").type == DuckDBMySQLSourceType::datetime,
       "recorded DATETIME is proven for a replica-managed column");
    ok(source_of("sales", "updated").type == DuckDBMySQLSourceType::timestamp,
       "recorded TIMESTAMP is distinguished from DATETIME on the same native type");
    ok(source_of("sales", "day").type == DuckDBMySQLSourceType::date, "recorded DATE is proven");
    auto note = source_of("sales", "note");
    ok(note.type == DuckDBMySQLSourceType::other && note.charset == "utf8mb4" &&
           note.collation == "utf8mb4_0900_bin",
       "text column keeps its recorded charset and collation");
    ok(source_of("sales", "id").known() && source_of("sales", "id").collation.empty(),
       "non-character column has known source and no collation");
    ok(!source_of("native_only", "created").known() && !source_of("native_only", "id").known(),
       "table absent from the replica manifest stays unknown despite recorded rows");
    ok(!source_of("sales_view", "created").known(), "views never carry source facts");
    setup_query(c, "UPDATE proxysql_replica.\"columns\" SET mysql_data_type = 'date' WHERE "
                   "column_name = 'amt'");
    ok(!source_of("sales", "amt").known(),
       "recorded type that disagrees with the native kind is ignored");
    setup_query(c, "DELETE FROM proxysql_replica.\"columns\" WHERE column_name = 'day'");
    ok(!source_of("sales", "day").known() && source_of("sales", "created").known(),
       "a missing record degrades only its own column");
    setup_query(c, "ALTER TABLE shop.sales ALTER note TYPE BLOB");
    ok(!source_of("sales", "note").known() && source_of("sales", "created").known(),
       "native ALTER that changes the stored type invalidates that column's facts");
    setup_query(c, "INSERT INTO proxysql_replica.tables VALUES ('s2','shop','sales','id')");
    setup_query(c, "INSERT INTO proxysql_replica.\"columns\" VALUES "
                   "('s2','shop','sales','id',1,'bigint','bigint(20)','','','BIGINT')");
    ok(!source_of("sales", "id").known() && source_of("sales", "created").known(),
       "two records for one column are ambiguous and degrade to unknown");

    // --- MySQL database namespace ----------------------------------------
    // A MySQL database maps to a schema of the current catalog. The selected
    // database overrides DuckDB's current_schema() for relative names, and a
    // qualified database.table name still names its own schema.
    setup_query(c, "CREATE SCHEMA ns_alpha");
    setup_query(c, "CREATE SCHEMA ns_beta");
    setup_query(c, "CREATE TABLE ns_alpha.same_name (a INTEGER)");
    setup_query(c, "CREATE TABLE ns_beta.same_name (b INTEGER)");
    setup_query(c, "SET schema = 'main'");
    context = duckdb_mysql_select_context(c, {}, "ns_beta", true);
    ok(context.default_schema == "ns_beta" && context.require_selected_database,
       "selected database is carried on the context");
    ok(context.resolve_relation({"same_name"}, r) && r.canonical_name.size() == 3 &&
           r.canonical_name[1] == "ns_beta" && r.columns.size() == 1 &&
           r.columns[0].canonical_name == "b",
       "relative name resolves in the selected database, not DuckDB's current schema");
    context = duckdb_mysql_select_context(c, {}, "ns_beta", true);
    ok(context.resolve_relation({"ns_alpha", "same_name"}, r) && r.canonical_name.size() == 3 &&
           r.canonical_name[1] == "ns_alpha",
       "qualified database.table resolves in its own schema");
    context = duckdb_mysql_select_context(c, {}, "ns_alpha", true);
    ok(!context.resolve_relation({"NS_BETA", "same_name"}, r) && r.columns.empty(),
       "a differently-cased database is not redirected to another schema");
    context = duckdb_mysql_select_context(c, {}, "", true);
    ok(!context.resolve_relation({"same_name"}, r) && r.columns.empty(),
       "relative name is refused when no database is selected");
    context = duckdb_mysql_select_context(c, {}, "", true);
    ok(context.resolve_relation({catalog, "ns_alpha", "same_name"}, r),
       "explicit catalog.schema.table still resolves without a selected database");
    context = duckdb_mysql_select_context(c, {}, "main", true);
    ok(!context.resolve_relation({"information_schema", "tables"}, r) && r.columns.empty(),
       "system schema is refused by the resolver");
    context = duckdb_mysql_select_context(c, {}, "", true);
    ok(!context.resolve_relation({"pg_catalog", "pg_class"}, r) && r.columns.empty(),
       "engine catalog schema is refused by the resolver");
    setup_query(c, "CREATE SCHEMA \"ns.dot\"");
    setup_query(c, "CREATE TABLE \"ns.dot\".dotted (a INTEGER)");
    context = duckdb_mysql_select_context(c, {}, "", true);
    ok(context.resolve_relation({"ns.dot", "dotted"}, r) && r.canonical_name.size() == 3 &&
           r.canonical_name[1] == "ns.dot",
       "a qualified name containing a dot resolves as one schema name");
    duckdb_disconnect(&c);
    duckdb_close(&db);
    return exit_status();
}
