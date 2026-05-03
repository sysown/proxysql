#include "sql_engine/in_memory_catalog.h"
#include <algorithm>
#include <cstring>

namespace sql_engine {

std::string InMemoryCatalog::to_lower(const char* s, size_t len) {
    std::string result(len, '\0');
    for (size_t i = 0; i < len; ++i) {
        char c = s[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        result[i] = c;
    }
    return result;
}

std::string InMemoryCatalog::make_key(const char* schema, const char* table) {
    std::string key;
    if (schema && schema[0] != '\0') {
        size_t slen = std::strlen(schema);
        key = to_lower(schema, slen);
        key += '.';
    }
    size_t tlen = std::strlen(table);
    key += to_lower(table, tlen);
    return key;
}

void InMemoryCatalog::add_table(const char* schema, const char* table,
                                 std::initializer_list<ColumnDef> columns) {
    std::string key = make_key(schema, table);

    TableData& td = tables_[key];
    td.schema_str = schema ? schema : "";
    td.table_str = table;
    td.column_names.clear();
    td.columns.clear();

    uint16_t ordinal = 0;
    for (const auto& def : columns) {
        td.column_names.emplace_back(def.name);
        ColumnInfo ci{};
        // StringRef will point into the stored string -- set after push_back
        ci.type = def.type;
        ci.ordinal = ordinal++;
        ci.nullable = def.nullable;
        td.columns.push_back(ci);
    }

    // Fix up StringRef pointers (must be done after all push_backs to avoid reallocation)
    for (size_t i = 0; i < td.columns.size(); ++i) {
        td.columns[i].name = sql_parser::StringRef{
            td.column_names[i].c_str(),
            static_cast<uint32_t>(td.column_names[i].size())
        };
    }

    // Set up TableInfo
    td.info.schema_name = sql_parser::StringRef{
        td.schema_str.c_str(),
        static_cast<uint32_t>(td.schema_str.size())
    };
    td.info.table_name = sql_parser::StringRef{
        td.table_str.c_str(),
        static_cast<uint32_t>(td.table_str.size())
    };
    td.info.columns = td.columns.data();
    td.info.column_count = static_cast<uint16_t>(td.columns.size());

    // Also register under unqualified name if schema is provided
    if (schema && schema[0] != '\0') {
        std::string unqualified = to_lower(table, std::strlen(table));
        // Only set unqualified key if it doesn't already exist or points to this same table
        if (tables_.find(unqualified) == tables_.end()) {
            // Store a reference entry: we don't duplicate, we just store another
            // entry pointing to the same data. But since we use value semantics,
            // we need to find via the qualified key. Instead, let get_table(name)
            // do a scan. Actually, for simplicity, store duplicate.
            // Better approach: unqualified lookup scans all entries.
        }
    }
}

void InMemoryCatalog::add_table(const char* schema, const char* table,
                                 const std::vector<ColumnDef>& columns) {
    // Delegate to the initializer_list version by reconstructing the same logic
    std::string key = make_key(schema, table);
    TableData& td = tables_[key];
    td.schema_str = schema ? schema : "";
    td.table_str = table;
    td.column_names.clear();
    td.columns.clear();
    uint16_t ordinal = 0;
    for (const auto& def : columns) {
        td.column_names.emplace_back(def.name);
        ColumnInfo ci{};
        ci.type = def.type;
        ci.ordinal = ordinal++;
        ci.nullable = def.nullable;
        td.columns.push_back(ci);
    }
    for (size_t i = 0; i < td.columns.size(); ++i) {
        td.columns[i].name = sql_parser::StringRef{
            td.column_names[i].c_str(),
            static_cast<uint32_t>(td.column_names[i].size())
        };
    }
    td.info.schema_name = sql_parser::StringRef{
        td.schema_str.c_str(), static_cast<uint32_t>(td.schema_str.size())
    };
    td.info.table_name = sql_parser::StringRef{
        td.table_str.c_str(), static_cast<uint32_t>(td.table_str.size())
    };
    td.info.columns = td.columns.data();
    td.info.column_count = static_cast<uint16_t>(td.columns.size());
}

void InMemoryCatalog::register_table(const TableInfo* table) {
    if (!table) return;
    std::string key = to_lower(table->table_name.ptr, table->table_name.len);

    TableData& td = tables_[key];
    td.schema_str = "";
    td.table_str = std::string(table->table_name.ptr, table->table_name.len);
    td.column_names.clear();
    td.columns.clear();

    for (uint16_t i = 0; i < table->column_count; ++i) {
        td.column_names.emplace_back(table->columns[i].name.ptr, table->columns[i].name.len);
        ColumnInfo ci = table->columns[i];
        td.columns.push_back(ci);
    }
    // Fix StringRef pointers
    for (size_t i = 0; i < td.columns.size(); ++i) {
        td.columns[i].name = sql_parser::StringRef{
            td.column_names[i].c_str(),
            static_cast<uint32_t>(td.column_names[i].size())
        };
    }
    td.info.schema_name = sql_parser::StringRef{
        td.schema_str.c_str(), static_cast<uint32_t>(td.schema_str.size())
    };
    td.info.table_name = sql_parser::StringRef{
        td.table_str.c_str(), static_cast<uint32_t>(td.table_str.size())
    };
    td.info.columns = td.columns.data();
    td.info.column_count = static_cast<uint16_t>(td.columns.size());
    td.info.alias = {};
}

void InMemoryCatalog::drop_table(const char* schema, const char* table) {
    std::string key = make_key(schema, table);
    tables_.erase(key);
}

const TableInfo* InMemoryCatalog::get_table(sql_parser::StringRef name) const {
    // Try exact (unqualified) lookup
    std::string lower = to_lower(name.ptr, name.len);
    auto it = tables_.find(lower);
    if (it != tables_.end()) return &it->second.info;

    // Scan for matching table_name (for qualified entries)
    for (const auto& pair : tables_) {
        const TableData& td = pair.second;
        if (td.info.table_name.equals_ci(name.ptr, name.len)) {
            return &td.info;
        }
    }
    return nullptr;
}

const TableInfo* InMemoryCatalog::get_table(sql_parser::StringRef schema,
                                             sql_parser::StringRef table) const {
    // Build qualified key
    std::string key = to_lower(schema.ptr, schema.len);
    key += '.';
    key += to_lower(table.ptr, table.len);
    auto it = tables_.find(key);
    if (it != tables_.end()) return &it->second.info;
    return nullptr;
}

const ColumnInfo* InMemoryCatalog::get_column(const TableInfo* table,
                                               sql_parser::StringRef column_name) const {
    if (!table) return nullptr;
    for (uint16_t i = 0; i < table->column_count; ++i) {
        if (table->columns[i].name.equals_ci(column_name.ptr, column_name.len)) {
            return &table->columns[i];
        }
    }
    return nullptr;
}

} // namespace sql_engine
