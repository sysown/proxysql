#include "PgSQLErrorFields.h"
#include <cstring>

PgSQLErrorResult pgsql_parse_error_response(const unsigned char* payload, size_t len) {
    PgSQLErrorResult result {};
    result.parsed = false;
    result.sqlstate[0] = '\0';
    result.message = nullptr;
    result.message_len = 0;

    if (!payload || len == 0) return result;
    result.parsed = true;

    size_t pos = 0;
    while (pos < len) {
        char field_type = static_cast<char>(payload[pos]);
        if (field_type == '\0') break;  // end of fields
        pos++;  // skip field type byte

        // Find the null terminator for this field's value
        const char* value = reinterpret_cast<const char*>(payload + pos);
        size_t value_len = strnlen(value, len - pos);
        if (pos + value_len >= len) break;  // truncated

        if (field_type == 'C' && value_len <= 5) {
            memcpy(result.sqlstate, value, value_len);
            result.sqlstate[value_len] = '\0';
        } else if (field_type == 'M') {
            result.message = value;
            result.message_len = value_len;
        }

        pos += value_len + 1;  // skip value + null terminator
    }

    return result;
}
