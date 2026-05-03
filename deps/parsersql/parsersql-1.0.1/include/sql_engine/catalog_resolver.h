#ifndef SQL_ENGINE_CATALOG_RESOLVER_H
#define SQL_ENGINE_CATALOG_RESOLVER_H

#include "sql_engine/catalog.h"
#include "sql_engine/value.h"

namespace sql_engine {

// Create a column resolver callback from catalog + table + row values.
// Returns a std::function<Value(StringRef)> suitable for evaluate_expression().
inline auto make_resolver(const Catalog& catalog,
                          const TableInfo* table,
                          const Value* row_values) {
    return [&catalog, table, row_values](sql_parser::StringRef col_name) -> Value {
        const ColumnInfo* col = catalog.get_column(table, col_name);
        if (!col) return value_null();
        return row_values[col->ordinal];
    };
}

} // namespace sql_engine

#endif // SQL_ENGINE_CATALOG_RESOLVER_H
