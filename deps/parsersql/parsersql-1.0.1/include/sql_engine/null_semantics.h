#ifndef SQL_ENGINE_NULL_SEMANTICS_H
#define SQL_ENGINE_NULL_SEMANTICS_H

#include "sql_engine/value.h"

namespace sql_engine {
namespace null_semantics {

// For most binary operators: if either operand is NULL, result is NULL.
// Returns true if NULL was propagated (caller should return `result` immediately).
inline bool propagate_null(const Value& left, const Value& right, Value& result) {
    if (left.is_null() || right.is_null()) {
        result = value_null();
        return true;
    }
    return false;
}

// Three-valued AND:
//   FALSE AND anything = FALSE
//   anything AND FALSE = FALSE
//   TRUE AND TRUE      = TRUE
//   NULL AND TRUE      = NULL
//   TRUE AND NULL      = NULL
//   NULL AND NULL      = NULL
inline Value eval_and(const Value& left, const Value& right) {
    // If either side is known FALSE, result is FALSE
    if (!left.is_null() && left.tag == Value::TAG_BOOL && !left.bool_val)
        return value_bool(false);
    if (!right.is_null() && right.tag == Value::TAG_BOOL && !right.bool_val)
        return value_bool(false);
    // If either side is NULL, result is NULL
    if (left.is_null() || right.is_null())
        return value_null();
    // Both are non-null booleans and neither is false, so both are true
    return value_bool(true);
}

// Three-valued OR:
//   TRUE OR anything = TRUE
//   anything OR TRUE = TRUE
//   FALSE OR FALSE   = FALSE
//   NULL OR FALSE    = NULL
//   FALSE OR NULL    = NULL
//   NULL OR NULL     = NULL
inline Value eval_or(const Value& left, const Value& right) {
    // If either side is known TRUE, result is TRUE
    if (!left.is_null() && left.tag == Value::TAG_BOOL && left.bool_val)
        return value_bool(true);
    if (!right.is_null() && right.tag == Value::TAG_BOOL && right.bool_val)
        return value_bool(true);
    // If either side is NULL, result is NULL
    if (left.is_null() || right.is_null())
        return value_null();
    // Both are non-null booleans and neither is true, so both are false
    return value_bool(false);
}

// NOT NULL = NULL, NOT TRUE = FALSE, NOT FALSE = TRUE
inline Value eval_not(const Value& val) {
    if (val.is_null()) return value_null();
    return value_bool(!val.bool_val);
}

} // namespace null_semantics
} // namespace sql_engine

#endif // SQL_ENGINE_NULL_SEMANTICS_H
