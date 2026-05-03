#ifndef SQL_ENGINE_FUNCTIONS_COMPARISON_H
#define SQL_ENGINE_FUNCTIONS_COMPARISON_H

#include "sql_engine/value.h"
#include "sql_parser/arena.h"

namespace sql_engine {
namespace functions {

using sql_parser::Arena;

// COALESCE(x, y, z, ...) -- first non-NULL argument
inline Value fn_coalesce(const Value* args, uint16_t arg_count, Arena& /*arena*/) {
    for (uint16_t i = 0; i < arg_count; ++i) {
        if (!args[i].is_null()) return args[i];
    }
    return value_null();
}

// NULLIF(x, y) -- returns NULL if x == y (same value), else x
inline Value fn_nullif(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() && args[1].is_null()) return value_null();
    if (args[0].is_null() || args[1].is_null()) return args[0];
    // Compare: both must be same tag and same value
    if (args[0].tag != args[1].tag) return args[0];
    switch (args[0].tag) {
        case Value::TAG_BOOL:
            return args[0].bool_val == args[1].bool_val ? value_null() : args[0];
        case Value::TAG_INT64:
            return args[0].int_val == args[1].int_val ? value_null() : args[0];
        case Value::TAG_UINT64:
            return args[0].uint_val == args[1].uint_val ? value_null() : args[0];
        case Value::TAG_DOUBLE:
            return args[0].double_val == args[1].double_val ? value_null() : args[0];
        case Value::TAG_STRING:
        case Value::TAG_DECIMAL:
        case Value::TAG_JSON:
            return args[0].str_val == args[1].str_val ? value_null() : args[0];
        default:
            return args[0];
    }
}

// IFNULL(x, y) -- MySQL: returns y if x is NULL, else x. Same as COALESCE(x, y).
inline Value fn_ifnull(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    return args[0].is_null() ? args[1] : args[0];
}

// IF(cond, then_val, else_val) -- MySQL: ternary
inline Value fn_if(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return args[2];
    // Truthy: non-zero for numeric, non-empty for string
    bool truthy = false;
    switch (args[0].tag) {
        case Value::TAG_BOOL:   truthy = args[0].bool_val; break;
        case Value::TAG_INT64:  truthy = args[0].int_val != 0; break;
        case Value::TAG_UINT64: truthy = args[0].uint_val != 0; break;
        case Value::TAG_DOUBLE: truthy = args[0].double_val != 0.0; break;
        default: truthy = true; break; // non-null non-numeric = truthy
    }
    return truthy ? args[1] : args[2];
}

// Helper: compare two numeric values. Returns <0, 0, >0.
inline int compare_values(const Value& a, const Value& b) {
    double da = a.to_double();
    double db = b.to_double();
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

// LEAST(x, y, ...) -- smallest non-NULL value. Returns NULL if all args are NULL.
inline Value fn_least(const Value* args, uint16_t arg_count, Arena& /*arena*/) {
    const Value* best = nullptr;
    for (uint16_t i = 0; i < arg_count; ++i) {
        if (args[i].is_null()) continue;
        if (!best || compare_values(args[i], *best) < 0) {
            best = &args[i];
        }
    }
    return best ? *best : value_null();
}

// GREATEST(x, y, ...) -- largest non-NULL value. Returns NULL if all args are NULL.
inline Value fn_greatest(const Value* args, uint16_t arg_count, Arena& /*arena*/) {
    const Value* best = nullptr;
    for (uint16_t i = 0; i < arg_count; ++i) {
        if (args[i].is_null()) continue;
        if (!best || compare_values(args[i], *best) > 0) {
            best = &args[i];
        }
    }
    return best ? *best : value_null();
}

} // namespace functions
} // namespace sql_engine

#endif // SQL_ENGINE_FUNCTIONS_COMPARISON_H
