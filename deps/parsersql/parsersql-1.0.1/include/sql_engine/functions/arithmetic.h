#ifndef SQL_ENGINE_FUNCTIONS_ARITHMETIC_H
#define SQL_ENGINE_FUNCTIONS_ARITHMETIC_H

#include "sql_engine/value.h"
#include "sql_engine/null_semantics.h"
#include "sql_parser/arena.h"
#include <cmath>
#include <cstdlib>

namespace sql_engine {
namespace functions {

using sql_parser::Arena;

// ABS(x) -- absolute value
inline Value fn_abs(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    switch (args[0].tag) {
        case Value::TAG_INT64:  return value_int(args[0].int_val < 0 ? -args[0].int_val : args[0].int_val);
        case Value::TAG_DOUBLE: return value_double(std::fabs(args[0].double_val));
        case Value::TAG_UINT64: return args[0]; // already unsigned
        default: return value_double(std::fabs(args[0].to_double()));
    }
}

// CEIL(x) / CEILING(x)
inline Value fn_ceil(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    if (args[0].tag == Value::TAG_INT64 || args[0].tag == Value::TAG_UINT64) return args[0];
    return value_double(std::ceil(args[0].to_double()));
}

// FLOOR(x)
inline Value fn_floor(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    if (args[0].tag == Value::TAG_INT64 || args[0].tag == Value::TAG_UINT64) return args[0];
    return value_double(std::floor(args[0].to_double()));
}

// ROUND(x) or ROUND(x, d)
inline Value fn_round(const Value* args, uint16_t arg_count, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    double v = args[0].to_double();
    int decimals = 0;
    if (arg_count >= 2 && !args[1].is_null()) {
        decimals = static_cast<int>(args[1].to_int64());
    }
    if (decimals == 0) {
        return value_double(std::round(v));
    }
    double factor = std::pow(10.0, decimals);
    return value_double(std::round(v * factor) / factor);
}

// TRUNCATE(x, d)
inline Value fn_truncate(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    double v = args[0].to_double();
    int decimals = static_cast<int>(args[1].to_int64());
    double factor = std::pow(10.0, decimals);
    return value_double(std::trunc(v * factor) / factor);
}

// MOD(x, y) -- modulo
inline Value fn_mod(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    // Integer mod if both are integer types
    if (args[0].tag == Value::TAG_INT64 && args[1].tag == Value::TAG_INT64) {
        if (args[1].int_val == 0) return value_null(); // division by zero
        return value_int(args[0].int_val % args[1].int_val);
    }
    double b = args[1].to_double();
    if (b == 0.0) return value_null();
    return value_double(std::fmod(args[0].to_double(), b));
}

// POWER(x, y) / POW(x, y)
inline Value fn_power(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null() || args[1].is_null()) return value_null();
    return value_double(std::pow(args[0].to_double(), args[1].to_double()));
}

// SQRT(x)
inline Value fn_sqrt(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    double v = args[0].to_double();
    if (v < 0.0) return value_null(); // domain error
    return value_double(std::sqrt(v));
}

// SIGN(x) -- returns -1, 0, or 1
inline Value fn_sign(const Value* args, uint16_t /*arg_count*/, Arena& /*arena*/) {
    if (args[0].is_null()) return value_null();
    double v = args[0].to_double();
    if (v > 0.0) return value_int(1);
    if (v < 0.0) return value_int(-1);
    return value_int(0);
}

} // namespace functions
} // namespace sql_engine

#endif // SQL_ENGINE_FUNCTIONS_ARITHMETIC_H
