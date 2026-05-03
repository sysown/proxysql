#ifndef SQL_ENGINE_TAG_KIND_MAP_H
#define SQL_ENGINE_TAG_KIND_MAP_H

#include "sql_engine/types.h"
#include "sql_engine/value.h"

namespace sql_engine {

// Convert a runtime Value::Tag to the corresponding SqlType::Kind.
// Used before calling CoercionRules<D>::common_type().
inline SqlType::Kind tag_to_kind(Value::Tag tag) {
    switch (tag) {
        case Value::TAG_NULL:      return SqlType::NULL_TYPE;
        case Value::TAG_BOOL:      return SqlType::BOOLEAN;
        case Value::TAG_INT64:     return SqlType::BIGINT;
        case Value::TAG_UINT64:    return SqlType::BIGINT;
        case Value::TAG_DOUBLE:    return SqlType::DOUBLE;
        case Value::TAG_DECIMAL:   return SqlType::DECIMAL;
        case Value::TAG_STRING:    return SqlType::VARCHAR;
        case Value::TAG_BYTES:     return SqlType::VARBINARY;
        case Value::TAG_DATE:      return SqlType::DATE;
        case Value::TAG_TIME:      return SqlType::TIME;
        case Value::TAG_DATETIME:  return SqlType::DATETIME;
        case Value::TAG_TIMESTAMP: return SqlType::TIMESTAMP;
        case Value::TAG_JSON:      return SqlType::JSON;
        default:                   return SqlType::UNKNOWN;
    }
}

// Convert a SqlType::Kind back to a Value::Tag for coercion targets.
// Used after common_type() returns the promotion target.
inline Value::Tag kind_to_tag(SqlType::Kind kind) {
    switch (kind) {
        case SqlType::BOOLEAN:                                return Value::TAG_BOOL;
        case SqlType::TINYINT:
        case SqlType::SMALLINT:
        case SqlType::MEDIUMINT:
        case SqlType::INT:
        case SqlType::BIGINT:                                 return Value::TAG_INT64;
        case SqlType::FLOAT:
        case SqlType::DOUBLE:                                 return Value::TAG_DOUBLE;
        case SqlType::DECIMAL:                                return Value::TAG_DECIMAL;
        case SqlType::CHAR:
        case SqlType::VARCHAR:
        case SqlType::TEXT:
        case SqlType::MEDIUMTEXT:
        case SqlType::LONGTEXT:                               return Value::TAG_STRING;
        case SqlType::BINARY:
        case SqlType::VARBINARY:
        case SqlType::BLOB:                                   return Value::TAG_BYTES;
        case SqlType::DATE:                                   return Value::TAG_DATE;
        case SqlType::TIME:                                   return Value::TAG_TIME;
        case SqlType::DATETIME:                               return Value::TAG_DATETIME;
        case SqlType::TIMESTAMP:                              return Value::TAG_TIMESTAMP;
        case SqlType::JSON:
        case SqlType::JSONB:                                  return Value::TAG_JSON;
        default:                                              return Value::TAG_NULL;
    }
}

} // namespace sql_engine

#endif // SQL_ENGINE_TAG_KIND_MAP_H
