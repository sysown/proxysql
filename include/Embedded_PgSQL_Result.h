#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "Embedded_Execution.h"
namespace embedded {
struct PgSQLColumn {
    TypeKind kind;
    bool nullable;
    std::string name;
    uint32_t oid;
    int16_t length;
    int32_t modifier;
};
Status pgsql_describe_columns(const std::vector<Column>&, std::vector<PgSQLColumn>&);
Status pgsql_result_format_supported(const PgSQLColumn&, int16_t format);
// Encodes one field payload only. On error payload is empty and is_null false.
Status pgsql_encode_field(const PgSQLColumn&, int16_t format, const Value&,
                          std::vector<unsigned char>& payload, bool& is_null,
                          size_t budget = 64u * 1024u * 1024u);
}  // namespace embedded
