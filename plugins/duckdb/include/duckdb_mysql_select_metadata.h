#pragma once

#include <cstddef>
#include <cstdint>
#include <duckdb.h>
#include <optional>
#include <string>
#include <vector>

// Native DuckDB facts only; these do not establish MySQL source semantics.
// The caller must hold its connection ownership guard for the whole call.
namespace duckdb_mysql_select_metadata {
enum class Status { available, invalid_request, native_error, resource_limit };
enum class CatalogProvenance { explicit_catalog, default_connection };
enum class Knowledge { unknown };
struct Column {
    std::string name;
    duckdb_type logical_type = DUCKDB_TYPE_INVALID;
    // Nested and otherwise unsupported IDs are retained above, not mapped.
    // True identifies a known scalar type; false includes nested and unclassified types.
    // This does not admit any translator operation.
    bool known_scalar_type = false;
    std::optional<uint8_t> decimal_precision;
    std::optional<uint8_t> decimal_scale;
    Knowledge nullable = Knowledge::unknown;
    Knowledge mysql_source_type = Knowledge::unknown;
    Knowledge mysql_collation = Knowledge::unknown;
};
struct Table {
    CatalogProvenance catalog_provenance = CatalogProvenance::default_connection;
    // Caller-supplied names, not canonical resolved names.
    std::optional<std::string> requested_catalog; // absent means default connection
    std::string requested_schema;
    std::string requested_table;
    std::vector<Column> columns;
};
struct Result {
    Status status = Status::invalid_request;
    std::string native_error;
    Table table;
    size_t metadata_bytes = 0;
};
// Null catalog uses DuckDB's current catalog; schema and table must be nonempty.
// remaining_budget bounds owned logical payload, including diagnostics, capped at 8 MiB.
// Fixed container overhead is excluded. metadata_bytes reports the returned payload charge.
Result describe(duckdb_connection connection, const std::optional<std::string> &catalog,
                const std::string &schema, const std::string &table,
                size_t remaining_budget = 8u * 1024u * 1024u);
} // namespace duckdb_mysql_select_metadata
