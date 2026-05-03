#ifndef SQL_ENGINE_IN_MEMORY_CATALOG_H
#define SQL_ENGINE_IN_MEMORY_CATALOG_H

#include "sql_engine/catalog.h"
#include <string>
#include <unordered_map>
#include <vector>
#include <initializer_list>

namespace sql_engine {

class InMemoryCatalog : public Catalog {
public:
    // Add a table with columns.
    void add_table(const char* schema, const char* table,
                   std::initializer_list<ColumnDef> columns);
    void add_table(const char* schema, const char* table,
                   const std::vector<ColumnDef>& columns);

    // Remove a table.
    void drop_table(const char* schema, const char* table);

    // Register a pre-built TableInfo (e.g., from CTE materialization)
    void register_table(const TableInfo* table) override;

    // Catalog interface
    const TableInfo* get_table(sql_parser::StringRef name) const override;
    const TableInfo* get_table(sql_parser::StringRef schema,
                                sql_parser::StringRef table) const override;
    const ColumnInfo* get_column(const TableInfo* table,
                                  sql_parser::StringRef column_name) const override;

private:
    // Internal storage: owns strings and column arrays.
    struct TableData {
        std::string schema_str;
        std::string table_str;
        std::vector<std::string> column_names;  // owns column name strings
        std::vector<ColumnInfo> columns;
        TableInfo info{};
    };

    // Key: lowercase "schema.table" or just lowercase "table"
    std::unordered_map<std::string, TableData> tables_;

    static std::string to_lower(const char* s, size_t len);
    static std::string make_key(const char* schema, const char* table);
};

} // namespace sql_engine

#endif // SQL_ENGINE_IN_MEMORY_CATALOG_H
