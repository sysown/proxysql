#include "duckdb_mysql_select_metadata.h"
#include <algorithm>
#include <cstring>
#include <memory>
#include <new>
#include <stdexcept>
#include <string_view>

namespace duckdb_mysql_select_metadata {
namespace {
constexpr size_t max_bytes = 8u * 1024u * 1024u;
constexpr size_t max_columns = 4096;
bool valid(const std::string &s) { return !s.empty() && s.find('\0') == std::string::npos; }
struct Description {
    duckdb_table_description value = nullptr;
    ~Description() { duckdb_table_description_destroy(&value); }
};
struct LogicalType {
    duckdb_logical_type value = nullptr;
    ~LogicalType() { duckdb_destroy_logical_type(&value); }
};
struct FreeName {
    void operator()(char *p) const { duckdb_free(p); }
};
bool scalar(duckdb_type t) {
    switch (t) {
    case DUCKDB_TYPE_BOOLEAN:
    case DUCKDB_TYPE_TINYINT:
    case DUCKDB_TYPE_SMALLINT:
    case DUCKDB_TYPE_INTEGER:
    case DUCKDB_TYPE_BIGINT:
    case DUCKDB_TYPE_UTINYINT:
    case DUCKDB_TYPE_USMALLINT:
    case DUCKDB_TYPE_UINTEGER:
    case DUCKDB_TYPE_UBIGINT:
    case DUCKDB_TYPE_FLOAT:
    case DUCKDB_TYPE_DOUBLE:
    case DUCKDB_TYPE_DECIMAL:
    case DUCKDB_TYPE_HUGEINT:
    case DUCKDB_TYPE_UHUGEINT:
    case DUCKDB_TYPE_VARCHAR:
    case DUCKDB_TYPE_BLOB:
    case DUCKDB_TYPE_DATE:
    case DUCKDB_TYPE_TIME:
    case DUCKDB_TYPE_TIMESTAMP:
    case DUCKDB_TYPE_TIMESTAMP_S:
    case DUCKDB_TYPE_TIMESTAMP_MS:
    case DUCKDB_TYPE_TIMESTAMP_NS:
    case DUCKDB_TYPE_TIMESTAMP_TZ:
    case DUCKDB_TYPE_TIME_TZ:
    case DUCKDB_TYPE_INTERVAL:
    case DUCKDB_TYPE_UUID:
    case DUCKDB_TYPE_BIT:
    case DUCKDB_TYPE_ENUM:
        return true;
    default:
        return false;
    }
}
} // namespace
Result describe(duckdb_connection conn, const std::optional<std::string> &catalog,
                const std::string &schema, const std::string &table, size_t remaining_budget) {
    Result result;
    if (!conn || !valid(schema) || !valid(table) || (catalog && !valid(*catalog)))
        return result;
    const size_t budget = std::min(remaining_budget, max_bytes);
    size_t used = 0;
    auto charge = [&](size_t n) {
        if (n > budget - used)
            return false;
        used += n;
        return true;
    };
    try {
        if (!charge(schema.size()) || !charge(table.size()) ||
            (catalog && !charge(catalog->size()))) {
            result.status = Status::resource_limit;
            return result;
        }
        Description desc;
        if (duckdb_table_description_create_ext(conn, catalog ? catalog->c_str() : nullptr,
                                                schema.c_str(), table.c_str(),
                                                &desc.value) != DuckDBSuccess) {
            const char *err = duckdb_table_description_error(desc.value);
            if (err)
                result.native_error.assign(err, strnlen(err, std::min<size_t>(4096, budget)));
            result.metadata_bytes = result.native_error.size();
            result.status = Status::native_error;
            return result;
        }
        const idx_t count = duckdb_table_description_get_column_count(desc.value);
        if (count == 0) {
            result.status = Status::native_error;
            return result;
        }
        if (count > max_columns || count > (budget - used) / sizeof(Column)) {
            result.status = Status::resource_limit;
            return result;
        }
        charge(static_cast<size_t>(count) * sizeof(Column));
        Table output;
        output.catalog_provenance =
            catalog ? CatalogProvenance::explicit_catalog : CatalogProvenance::default_connection;
        output.requested_catalog = catalog;
        output.requested_schema = schema;
        output.requested_table = table;
        output.columns.reserve(static_cast<size_t>(count));
        for (idx_t i = 0; i < count; ++i) {
            std::unique_ptr<char, FreeName> name(
                duckdb_table_description_get_column_name(desc.value, i));
            LogicalType type{duckdb_table_description_get_column_type(desc.value, i)};
            if (!name || !type.value) {
                result.status = Status::native_error;
                return result;
            }
            // DuckDB returns a NUL-terminated name that the unique_ptr frees.
            const std::string_view name_view(name.get());
            if (!charge(name_view.size())) {
                result.status = Status::resource_limit;
                return result;
            }
            Column col;
            col.name.assign(name_view.data(), name_view.size());
            col.logical_type = duckdb_get_type_id(type.value);
            col.known_scalar_type = scalar(col.logical_type);
            if (col.logical_type == DUCKDB_TYPE_DECIMAL) {
                col.decimal_precision = duckdb_decimal_width(type.value);
                col.decimal_scale = duckdb_decimal_scale(type.value);
            }
            output.columns.push_back(std::move(col));
        }
        result.table = std::move(output);
        result.metadata_bytes = used;
        result.status = Status::available;
    } catch (const std::bad_alloc &) {
        result.status = Status::resource_limit;
    } catch (const std::length_error &) {
        result.status = Status::resource_limit;
    }
    return result;
}
} // namespace duckdb_mysql_select_metadata
