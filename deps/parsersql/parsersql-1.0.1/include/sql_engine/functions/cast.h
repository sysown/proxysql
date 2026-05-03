#ifndef SQL_ENGINE_FUNCTIONS_CAST_H
#define SQL_ENGINE_FUNCTIONS_CAST_H

#include "sql_engine/types.h"
#include "sql_engine/value.h"
#include "sql_engine/coercion.h"
#include "sql_engine/datetime_parse.h"
#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <cstdio>
#include <cstring>

namespace sql_engine {
namespace functions {

// Cast a Value to a target SqlType::Kind.
// Explicit casts are more permissive than implicit coercion -- even PostgreSQL
// allows explicit CAST(string AS int).
template <sql_parser::Dialect D>
Value cast_value(const Value& val, SqlType::Kind target, sql_parser::Arena& arena) {
    if (val.is_null()) return value_null();

    // Map SqlType::Kind to Value::Tag for the target
    Value::Tag target_tag;
    switch (target) {
        case SqlType::BOOLEAN:   target_tag = Value::TAG_BOOL; break;
        case SqlType::TINYINT:
        case SqlType::SMALLINT:
        case SqlType::MEDIUMINT:
        case SqlType::INT:
        case SqlType::BIGINT:    target_tag = Value::TAG_INT64; break;
        case SqlType::FLOAT:
        case SqlType::DOUBLE:    target_tag = Value::TAG_DOUBLE; break;
        case SqlType::DECIMAL:   target_tag = Value::TAG_DECIMAL; break;
        case SqlType::CHAR:
        case SqlType::VARCHAR:
        case SqlType::TEXT:
        case SqlType::MEDIUMTEXT:
        case SqlType::LONGTEXT:  target_tag = Value::TAG_STRING; break;
        case SqlType::DATE:      target_tag = Value::TAG_DATE; break;
        case SqlType::TIME:      target_tag = Value::TAG_TIME; break;
        case SqlType::DATETIME:  target_tag = Value::TAG_DATETIME; break;
        case SqlType::TIMESTAMP: target_tag = Value::TAG_TIMESTAMP; break;
        default:                 return value_null(); // unsupported cast target
    }

    if (val.tag == target_tag) return val;

    // For explicit casts, use MySQL-style coercion (lenient) even for Pg,
    // but validate strictly for PostgreSQL.
    if constexpr (D == sql_parser::Dialect::MySQL) {
        return CoercionRules<sql_parser::Dialect::MySQL>::coerce_value(val, target_tag, arena);
    } else {
        // PostgreSQL: explicit casts allow string->int etc., but strictly
        switch (target_tag) {
            case Value::TAG_INT64: {
                if (val.tag == Value::TAG_BOOL) return value_int(val.bool_val ? 1 : 0);
                if (val.tag == Value::TAG_UINT64) return value_int(static_cast<int64_t>(val.uint_val));
                if (val.tag == Value::TAG_DOUBLE) return value_int(static_cast<int64_t>(val.double_val));
                if (val.tag == Value::TAG_STRING || val.tag == Value::TAG_DECIMAL) {
                    int64_t out;
                    if (detail::parse_int_strict(val.str_val.ptr, val.str_val.len, out))
                        return value_int(out);
                    return value_null(); // parse error
                }
                return value_null();
            }
            case Value::TAG_DOUBLE: {
                if (val.tag == Value::TAG_BOOL) return value_double(val.bool_val ? 1.0 : 0.0);
                if (val.tag == Value::TAG_INT64) return value_double(static_cast<double>(val.int_val));
                if (val.tag == Value::TAG_UINT64) return value_double(static_cast<double>(val.uint_val));
                if (val.tag == Value::TAG_STRING || val.tag == Value::TAG_DECIMAL) {
                    double out;
                    if (detail::parse_double_lenient(val.str_val.ptr, val.str_val.len, out))
                        return value_double(out);
                    return value_null();
                }
                return value_null();
            }
            case Value::TAG_STRING: {
                if (val.tag == Value::TAG_INT64)
                    return value_string(detail::int_to_string(val.int_val, arena));
                if (val.tag == Value::TAG_DOUBLE)
                    return value_string(detail::double_to_string(val.double_val, arena));
                if (val.tag == Value::TAG_BOOL)
                    return value_string(val.bool_val
                        ? arena.allocate_string("true", 4)
                        : arena.allocate_string("false", 5));
                return value_null();
            }
            case Value::TAG_BOOL: {
                if (val.tag == Value::TAG_INT64) return value_bool(val.int_val != 0);
                if (val.tag == Value::TAG_STRING) {
                    // PostgreSQL: 'true'/'t'/'1'/'yes'/'on' -> true
                    if (val.str_val.equals_ci("true", 4) || val.str_val.equals_ci("t", 1) ||
                        val.str_val.equals_ci("1", 1) || val.str_val.equals_ci("yes", 3) ||
                        val.str_val.equals_ci("on", 2))
                        return value_bool(true);
                    if (val.str_val.equals_ci("false", 5) || val.str_val.equals_ci("f", 1) ||
                        val.str_val.equals_ci("0", 1) || val.str_val.equals_ci("no", 2) ||
                        val.str_val.equals_ci("off", 3))
                        return value_bool(false);
                    return value_null();
                }
                return value_null();
            }
            case Value::TAG_DATE: {
                if (val.tag == Value::TAG_STRING && val.str_val.ptr && val.str_val.len > 0) {
                    char buf[32];
                    uint32_t n = val.str_val.len < 31 ? val.str_val.len : 31;
                    std::memcpy(buf, val.str_val.ptr, n);
                    buf[n] = '\0';
                    return value_date(datetime_parse::parse_date(buf));
                }
                return value_null();
            }
            case Value::TAG_TIME: {
                if (val.tag == Value::TAG_STRING && val.str_val.ptr && val.str_val.len > 0) {
                    char buf[32];
                    uint32_t n = val.str_val.len < 31 ? val.str_val.len : 31;
                    std::memcpy(buf, val.str_val.ptr, n);
                    buf[n] = '\0';
                    return value_time(datetime_parse::parse_time(buf));
                }
                return value_null();
            }
            case Value::TAG_DATETIME: {
                if (val.tag == Value::TAG_STRING && val.str_val.ptr && val.str_val.len > 0) {
                    char buf[64];
                    uint32_t n = val.str_val.len < 63 ? val.str_val.len : 63;
                    std::memcpy(buf, val.str_val.ptr, n);
                    buf[n] = '\0';
                    return value_datetime(datetime_parse::parse_datetime(buf));
                }
                return value_null();
            }
            case Value::TAG_TIMESTAMP: {
                if (val.tag == Value::TAG_STRING && val.str_val.ptr && val.str_val.len > 0) {
                    char buf[64];
                    uint32_t n = val.str_val.len < 63 ? val.str_val.len : 63;
                    std::memcpy(buf, val.str_val.ptr, n);
                    buf[n] = '\0';
                    return value_timestamp(datetime_parse::parse_datetime_tz(buf));
                }
                return value_null();
            }
            default:
                return value_null();
        }
    }
}

} // namespace functions
} // namespace sql_engine

#endif // SQL_ENGINE_FUNCTIONS_CAST_H
