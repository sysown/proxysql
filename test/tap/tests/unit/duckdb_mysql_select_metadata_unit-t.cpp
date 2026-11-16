#include "duckdb_mysql_select_metadata.h"
#include "tap.h"
#include <iostream>
#include <string>
using namespace duckdb_mysql_select_metadata;
static void sql(duckdb_connection c, const std::string &s) {
    duckdb_result r{};
    auto status = duckdb_query(c, s.c_str(), &r);
    if (status != DuckDBSuccess)
        std::cerr << duckdb_result_error(&r) << '\n';
    if (status != DuckDBSuccess)
        BAIL_OUT("fixture SQL failed");
    duckdb_destroy_result(&r);
}
int main() {
    plan(NO_PLAN);
    duckdb_database db{};
    duckdb_connection c{};
    if (duckdb_open(nullptr, &db) != DuckDBSuccess || duckdb_connect(db, &c) != DuckDBSuccess)
        BAIL_OUT("cannot open DuckDB fixture");
    sql(c, "CREATE TABLE \"odd table\" (\"é\" DECIMAL(18,4) NOT NULL, bin BLOB, n HUGEINT, d DATE, "
           "nested INTEGER[])");
    auto r = describe(c, std::nullopt, "main", "odd table");
    ok(r.status == Status::available && !r.table.requested_catalog &&
           r.table.catalog_provenance == CatalogProvenance::default_connection,
       "default catalog provenance");
    ok(r.table.columns.size() == 5, "column count");
    if (r.table.columns.size() != 5)
        BAIL_OUT("metadata fixture lacks columns");
    ok(r.table.columns[0].name == "é", "UTF-8 column name");
    ok(r.table.columns[0].logical_type == DUCKDB_TYPE_DECIMAL &&
           r.table.columns[0].decimal_precision == 18 && r.table.columns[0].decimal_scale == 4,
       "decimal type precision and scale");
    ok(r.table.columns[0].nullable == Knowledge::unknown &&
           r.table.columns[0].mysql_source_type == Knowledge::unknown &&
           r.table.columns[0].mysql_collation == Knowledge::unknown,
       "unknown source facts and nullability");
    ok(r.table.columns[1].logical_type == DUCKDB_TYPE_BLOB &&
           r.table.columns[2].logical_type == DUCKDB_TYPE_HUGEINT &&
           r.table.columns[3].logical_type == DUCKDB_TYPE_DATE,
       "blob hugeint and date types");
    ok(r.table.columns[4].logical_type == DUCKDB_TYPE_LIST && !r.table.columns[4].known_scalar_type,
       "nested type remains unsupported");
    ok(describe(c, std::nullopt, "main", std::string("bad\0name", 8)).status ==
           Status::invalid_request,
       "embedded NUL rejected");
    auto limited = describe(c, std::nullopt, "main", "odd table", 1);
    ok(limited.status == Status::resource_limit && limited.table.columns.empty() &&
           limited.table.requested_schema.empty() && limited.table.requested_table.empty(),
       "budget failure has no partial result");
    ok(describe(nullptr, std::nullopt, "main", "odd table").status == Status::invalid_request,
       "null connection rejected");
    ok(describe(c, std::nullopt, std::string("ma\0in", 5), "odd table").status ==
           Status::invalid_request,
       "embedded NUL in schema rejected");
    ok(describe(c, std::string("ca\0t", 4), "main", "odd table").status == Status::invalid_request,
       "embedded NUL in catalog rejected");
    auto different_case = describe(c, std::nullopt, "MAIN", "ODD TABLE");
    ok(different_case.status == Status::available &&
           different_case.table.requested_schema == "MAIN" &&
           different_case.table.requested_table == "ODD TABLE" &&
           !different_case.table.columns.empty() && different_case.table.columns[0].name == "é",
       "requested names retained; column name from native metadata");
    ok(describe(c, std::string(""), "main", "odd table").status == Status::invalid_request,
       "empty explicit catalog rejected");
    ok(describe(c, std::nullopt, "", "odd table").status == Status::invalid_request,
       "empty schema rejected");
    ok(describe(c, std::nullopt, "main", "odd table", SIZE_MAX).status == Status::available,
       "large budget accepted");
    auto missing = describe(c, std::nullopt, "main", "missing");
    ok(missing.status == Status::native_error && !missing.native_error.empty(),
       "missing table preserves native error");
    const size_t failure_budget = std::string("main").size() + std::string("missing").size();
    auto bounded_error = describe(c, std::nullopt, "main", "missing", failure_budget);
    ok(bounded_error.status == Status::native_error &&
           bounded_error.native_error.size() <= failure_budget &&
           bounded_error.metadata_bytes == bounded_error.native_error.size() &&
           bounded_error.table.columns.empty() && bounded_error.table.requested_schema.empty() &&
           bounded_error.table.requested_table.empty(),
       "native diagnostic respects budget and no partial table");
    ok(describe(c, std::nullopt, "main", "missing", failure_budget - 1).status ==
           Status::resource_limit,
       "insufficient budget rejected before native lookup");
    ok(describe(c, std::nullopt, "missing", "x").status == Status::native_error,
       "missing schema error");
    ok(describe(c, std::string("missing"), "main", "x").status == Status::native_error,
       "missing catalog error");
    sql(c, "ALTER TABLE \"odd table\" ADD COLUMN added INTEGER");
    ok(describe(c, std::nullopt, "main", "odd table").table.columns.size() == 6, "DDL refresh");
    sql(c, "BEGIN TRANSACTION");
    sql(c, "CREATE TABLE tx_table (a INTEGER)");
    ok(describe(c, std::nullopt, "main", "tx_table").status == Status::available,
       "transaction metadata visible");
    sql(c, "ROLLBACK");
    ok(describe(c, std::nullopt, "main", "tx_table").status == Status::native_error,
       "rollback remains effective");
    std::string wide = "CREATE TABLE wide (";
    for (int i = 0; i < 4097; ++i) {
        if (i)
            wide += ',';
        wide += "c" + std::to_string(i) + " INTEGER";
    }
    sql(c, wide + ")");
    ok(describe(c, std::nullopt, "main", "wide").status == Status::resource_limit,
       "column count limit");
    ok(describe(c, std::nullopt, "main", "odd table").status == Status::available,
       "connection reusable after failure");
    duckdb_disconnect(&c);
    duckdb_close(&db);
    return exit_status();
}
