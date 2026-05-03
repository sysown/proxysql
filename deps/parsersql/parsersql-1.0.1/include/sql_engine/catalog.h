// catalog.h — Table and column metadata interface
//
// The Catalog abstract class is the contract between the query engine and
// the metadata store. Implementations must provide:
//
//   get_table(name)           — lookup by unqualified table name
//   get_table(schema, table)  — lookup by qualified schema.table name
//   get_column(table, name)   — find a column within a resolved table
//
// TableInfo and ColumnInfo must remain valid for the lifetime of any query
// that references them. ColumnInfo::ordinal must match the column's
// position in rows produced by the corresponding DataSource.
//
// See in_memory_catalog.h for the hash-map implementation. To integrate
// with an external metadata store, implement this interface directly.

#ifndef SQL_ENGINE_CATALOG_H
#define SQL_ENGINE_CATALOG_H

#include "sql_engine/types.h"
#include "sql_parser/common.h"
#include <cstdint>

namespace sql_engine {

struct ColumnInfo {
    sql_parser::StringRef name;
    SqlType type;
    uint16_t ordinal;       // 0-based position in table
    bool nullable;
};

struct TableInfo {
    sql_parser::StringRef schema_name;  // empty if default/no schema
    sql_parser::StringRef table_name;
    const ColumnInfo* columns;
    uint16_t column_count;
    sql_parser::StringRef alias;        // table alias (empty if no alias)
};

// Convenience for building columns programmatically
struct ColumnDef {
    const char* name;
    SqlType type;
    bool nullable = true;
};

class Catalog {
public:
    virtual ~Catalog() = default;

    // Find a table by unqualified name. Returns nullptr if not found.
    virtual const TableInfo* get_table(sql_parser::StringRef name) const = 0;

    // Find a table by qualified name (schema.table). Returns nullptr if not found.
    virtual const TableInfo* get_table(sql_parser::StringRef schema,
                                        sql_parser::StringRef table) const = 0;

    // Find a column in a table by name. Returns nullptr if not found.
    virtual const ColumnInfo* get_column(const TableInfo* table,
                                          sql_parser::StringRef column_name) const = 0;

    // Register a pre-built TableInfo (e.g., for CTEs). Default: no-op.
    virtual void register_table(const TableInfo* /*table*/) {}
};

} // namespace sql_engine

#endif // SQL_ENGINE_CATALOG_H
