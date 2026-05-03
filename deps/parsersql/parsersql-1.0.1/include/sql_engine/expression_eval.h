// expression_eval.h — Recursive AST expression evaluator
//
// Core function: evaluate_expression<D>(expr, resolve, functions, arena, subquery_exec)
//
// Takes a parsed AST expression node and evaluates it recursively against
// a row of data. The `resolve` callback maps column names (StringRef) to
// Values — typically built via make_resolver() from catalog_resolver.h.
//
// Supports: literals, column refs, qualified names (table.column),
// arithmetic (+, -, *, /, %), comparisons (=, <>, <, >, <=, >=),
// boolean logic (AND, OR, NOT) with three-valued NULL semantics,
// IS [NOT] NULL, BETWEEN, IN, LIKE, CASE/WHEN, function calls via
// FunctionRegistry, unary minus, and dialect-specific || (concat in
// PostgreSQL, OR in MySQL).
//
// Type coercion is handled automatically via CoercionRules<D>. NULL
// propagates through most operators (exceptions: IS NULL, AND, OR).
// Returns value_null() for unsupported or erroneous expressions.

#ifndef SQL_ENGINE_EXPRESSION_EVAL_H
#define SQL_ENGINE_EXPRESSION_EVAL_H

#include "sql_engine/value.h"
#include "sql_engine/types.h"
#include "sql_engine/null_semantics.h"
#include "sql_engine/coercion.h"
#include "sql_engine/tag_kind_map.h"
#include "sql_engine/like.h"
#include "sql_engine/function_registry.h"
#include "sql_engine/subquery_executor.h"
#include "sql_parser/common.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include <functional>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>

namespace sql_engine {

using sql_parser::Dialect;
using sql_parser::Arena;
using sql_parser::AstNode;
using sql_parser::NodeType;
using sql_parser::StringRef;

namespace detail {

// Count children of an AST node.
inline uint32_t child_count(const AstNode* node) {
    uint32_t n = 0;
    for (const AstNode* c = node->first_child; c; c = c->next_sibling) ++n;
    return n;
}

// Get the Nth child (0-based). Returns nullptr if out of bounds.
inline const AstNode* nth_child(const AstNode* node, uint32_t index) {
    const AstNode* c = node->first_child;
    for (uint32_t i = 0; c && i < index; ++i) c = c->next_sibling;
    return c;
}

// Parse a null-terminated-ish StringRef as int64 via strtoll.
inline int64_t parse_int_from_ref(StringRef ref) {
    if (ref.len == 0) return 0;
    char buf[64];
    uint32_t n = ref.len < 63 ? ref.len : 63;
    std::memcpy(buf, ref.ptr, n);
    buf[n] = '\0';
    return std::strtoll(buf, nullptr, 10);
}

// Parse a StringRef as double via strtod.
inline double parse_double_from_ref(StringRef ref) {
    if (ref.len == 0) return 0.0;
    char buf[128];
    uint32_t n = ref.len < 127 ? ref.len : 127;
    std::memcpy(buf, ref.ptr, n);
    buf[n] = '\0';
    return std::strtod(buf, nullptr);
}

// Case-insensitive comparison of StringRef against a C-string literal.
inline bool ref_equals_ci(StringRef ref, const char* s, uint32_t slen) {
    return ref.equals_ci(s, slen);
}

} // namespace detail

// ============================================================
// evaluate_expression<D>()
//
// Evaluates a single AST expression node recursively.
// Returns value_null() on error or unsupported nodes.
// ============================================================

template <Dialect D>
Value evaluate_expression(const AstNode* expr,
                          const std::function<Value(StringRef)>& resolve,
                          FunctionRegistry<D>& functions,
                          Arena& arena,
                          SubqueryExecutor<D>* subquery_exec = nullptr) {
    if (!expr) return value_null();

    switch (expr->type) {

    // ---- Leaf nodes ----

    case NodeType::NODE_LITERAL_INT: {
        // Check for TRUE/FALSE keywords (parser stores them as NODE_LITERAL_INT)
        StringRef val = expr->value();
        if (detail::ref_equals_ci(val, "TRUE", 4))
            return value_bool(true);
        if (detail::ref_equals_ci(val, "FALSE", 5))
            return value_bool(false);
        return value_int(detail::parse_int_from_ref(val));
    }

    case NodeType::NODE_LITERAL_FLOAT: {
        return value_double(detail::parse_double_from_ref(expr->value()));
    }

    case NodeType::NODE_LITERAL_STRING: {
        return value_string(expr->value());
    }

    case NodeType::NODE_LITERAL_NULL: {
        return value_null();
    }

    case NodeType::NODE_COLUMN_REF: {
        return resolve(expr->value());
    }

    case NodeType::NODE_IDENTIFIER: {
        return resolve(expr->value());
    }

    case NodeType::NODE_ASTERISK: {
        return value_string(StringRef{"*", 1});
    }

    case NodeType::NODE_PLACEHOLDER: {
        return value_null();  // unresolved placeholder
    }

    // ---- Qualified name: combine table.column, call resolve ----

    case NodeType::NODE_QUALIFIED_NAME: {
        const AstNode* tbl = detail::nth_child(expr, 0);
        const AstNode* col = detail::nth_child(expr, 1);
        if (!tbl || !col) return value_null();
        // Build "table.column" string in arena
        StringRef t = tbl->value();
        StringRef c = col->value();
        uint32_t total = t.len + 1 + c.len;
        char* buf = static_cast<char*>(arena.allocate(total));
        if (!buf) return value_null();
        std::memcpy(buf, t.ptr, t.len);
        buf[t.len] = '.';
        std::memcpy(buf + t.len + 1, c.ptr, c.len);
        return resolve(StringRef{buf, total});
    }

    // ---- Wrapper: unwrap and evaluate first child ----

    case NodeType::NODE_EXPRESSION: {
        return evaluate_expression<D>(expr->first_child, resolve, functions, arena, subquery_exec);
    }

    // ---- Unary operators ----

    case NodeType::NODE_UNARY_OP: {
        StringRef op = expr->value();
        const AstNode* operand_node = expr->first_child;
        if (!operand_node) return value_null();
        Value operand = evaluate_expression<D>(operand_node, resolve, functions, arena, subquery_exec);
        if (op.len == 1 && op.ptr[0] == '-') {
            // Unary minus
            if (operand.is_null()) return value_null();
            if (operand.tag == Value::TAG_INT64)
                return value_int(-operand.int_val);
            if (operand.tag == Value::TAG_DOUBLE)
                return value_double(-operand.double_val);
            if (operand.tag == Value::TAG_UINT64)
                return value_int(-static_cast<int64_t>(operand.uint_val));
            return value_null();
        }
        if (detail::ref_equals_ci(op, "NOT", 3)) {
            // Three-valued NOT: NULL->NULL, TRUE->FALSE, FALSE->TRUE
            if (operand.is_null()) return value_null();
            if (operand.tag == Value::TAG_BOOL)
                return null_semantics::eval_not(operand);
            // For numeric: 0 is false, non-zero is true
            if (operand.tag == Value::TAG_INT64)
                return value_bool(operand.int_val == 0);
            if (operand.tag == Value::TAG_DOUBLE)
                return value_bool(operand.double_val == 0.0);
            return value_bool(false);  // non-null non-numeric = truthy, NOT = false
        }
        return value_null();
    }

    // ---- Binary operators ----

    case NodeType::NODE_BINARY_OP: {
        StringRef op = expr->value();
        const AstNode* left_node = detail::nth_child(expr, 0);
        const AstNode* right_node = detail::nth_child(expr, 1);
        if (!left_node || !right_node) return value_null();

        // --- Short-circuit: AND ---
        if (detail::ref_equals_ci(op, "AND", 3)) {
            Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
            // If left is FALSE -> FALSE immediately
            if (!left_val.is_null() && left_val.tag == Value::TAG_BOOL && !left_val.bool_val)
                return value_bool(false);
            Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
            return null_semantics::eval_and(left_val, right_val);
        }

        // --- Short-circuit: OR ---
        if (detail::ref_equals_ci(op, "OR", 2)) {
            Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
            // If left is TRUE -> TRUE immediately
            if (!left_val.is_null() && left_val.tag == Value::TAG_BOOL && left_val.bool_val)
                return value_bool(true);
            Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
            return null_semantics::eval_or(left_val, right_val);
        }

        // --- IS / IS NOT (never return NULL) ---
        if (detail::ref_equals_ci(op, "IS", 2)) {
            Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
            Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
            // IS TRUE: left is truthy and not null
            if (!right_val.is_null() && right_val.tag == Value::TAG_BOOL && right_val.bool_val) {
                // IS TRUE
                if (left_val.is_null()) return value_bool(false);
                if (left_val.tag == Value::TAG_BOOL) return value_bool(left_val.bool_val);
                if (left_val.tag == Value::TAG_INT64) return value_bool(left_val.int_val != 0);
                if (left_val.tag == Value::TAG_DOUBLE) return value_bool(left_val.double_val != 0.0);
                return value_bool(true);  // non-null = truthy
            }
            // IS FALSE: left is falsy and not null
            if (!right_val.is_null() && right_val.tag == Value::TAG_BOOL && !right_val.bool_val) {
                if (left_val.is_null()) return value_bool(false);
                if (left_val.tag == Value::TAG_BOOL) return value_bool(!left_val.bool_val);
                if (left_val.tag == Value::TAG_INT64) return value_bool(left_val.int_val == 0);
                if (left_val.tag == Value::TAG_DOUBLE) return value_bool(left_val.double_val == 0.0);
                return value_bool(false);  // non-null non-numeric = truthy, so not false
            }
            return value_null();
        }
        if (detail::ref_equals_ci(op, "IS NOT", 6)) {
            Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
            Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
            // IS NOT TRUE = NOT (IS TRUE)
            if (!right_val.is_null() && right_val.tag == Value::TAG_BOOL && right_val.bool_val) {
                if (left_val.is_null()) return value_bool(true);
                if (left_val.tag == Value::TAG_BOOL) return value_bool(!left_val.bool_val);
                if (left_val.tag == Value::TAG_INT64) return value_bool(left_val.int_val == 0);
                if (left_val.tag == Value::TAG_DOUBLE) return value_bool(left_val.double_val == 0.0);
                return value_bool(false);
            }
            // IS NOT FALSE = NOT (IS FALSE)
            if (!right_val.is_null() && right_val.tag == Value::TAG_BOOL && !right_val.bool_val) {
                if (left_val.is_null()) return value_bool(true);
                if (left_val.tag == Value::TAG_BOOL) return value_bool(left_val.bool_val);
                if (left_val.tag == Value::TAG_INT64) return value_bool(left_val.int_val != 0);
                if (left_val.tag == Value::TAG_DOUBLE) return value_bool(left_val.double_val != 0.0);
                return value_bool(true);
            }
            return value_null();
        }

        // --- LIKE ---
        if (detail::ref_equals_ci(op, "LIKE", 4)) {
            Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
            Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
            if (left_val.is_null() || right_val.is_null()) return value_null();
            // Coerce both to strings if not already
            if (left_val.tag != Value::TAG_STRING)
                left_val = CoercionRules<D>::coerce_value(left_val, Value::TAG_STRING, arena);
            if (right_val.tag != Value::TAG_STRING)
                right_val = CoercionRules<D>::coerce_value(right_val, Value::TAG_STRING, arena);
            if (left_val.is_null() || right_val.is_null()) return value_null();
            return value_bool(match_like<D>(left_val.str_val, right_val.str_val));
        }

        // --- || : PostgreSQL = concat, MySQL = OR ---
        if (op.len == 2 && op.ptr[0] == '|' && op.ptr[1] == '|') {
            if constexpr (D == Dialect::PostgreSQL) {
                // String concatenation
                Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
                Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
                if (left_val.is_null() || right_val.is_null()) return value_null();
                // Coerce to string
                if (left_val.tag != Value::TAG_STRING)
                    left_val = CoercionRules<D>::coerce_value(left_val, Value::TAG_STRING, arena);
                if (right_val.tag != Value::TAG_STRING)
                    right_val = CoercionRules<D>::coerce_value(right_val, Value::TAG_STRING, arena);
                if (left_val.is_null() || right_val.is_null()) return value_null();
                uint32_t total = left_val.str_val.len + right_val.str_val.len;
                if (total == 0) return value_string(StringRef{nullptr, 0});
                char* buf = static_cast<char*>(arena.allocate(total));
                if (!buf) return value_null();
                std::memcpy(buf, left_val.str_val.ptr, left_val.str_val.len);
                std::memcpy(buf + left_val.str_val.len, right_val.str_val.ptr, right_val.str_val.len);
                return value_string(StringRef{buf, total});
            } else {
                // MySQL: || is OR
                Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
                if (!left_val.is_null() && left_val.tag == Value::TAG_BOOL && left_val.bool_val)
                    return value_bool(true);
                Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);
                return null_semantics::eval_or(left_val, right_val);
            }
        }

        // --- Standard binary: evaluate both sides, null-propagate, coerce, apply ---
        Value left_val = evaluate_expression<D>(left_node, resolve, functions, arena, subquery_exec);
        Value right_val = evaluate_expression<D>(right_node, resolve, functions, arena, subquery_exec);

        // NULL propagation
        if (left_val.is_null() || right_val.is_null()) return value_null();

        // Map to SqlType::Kind for coercion
        SqlType::Kind left_kind = tag_to_kind(left_val.tag);
        SqlType::Kind right_kind = tag_to_kind(right_val.tag);
        SqlType::Kind common = CoercionRules<D>::common_type(left_kind, right_kind);
        if (common == SqlType::UNKNOWN) return value_null();
        Value::Tag target_tag = kind_to_tag(common);

        // Coerce both to common type
        Value lv = CoercionRules<D>::coerce_value(left_val, target_tag, arena);
        Value rv = CoercionRules<D>::coerce_value(right_val, target_tag, arena);
        if (lv.is_null() || rv.is_null()) return value_null();

        // --- Arithmetic operators ---
        if (op.len == 1) {
            switch (op.ptr[0]) {
                case '+':
                    if (lv.tag == Value::TAG_INT64) return value_int(lv.int_val + rv.int_val);
                    if (lv.tag == Value::TAG_DOUBLE) return value_double(lv.double_val + rv.double_val);
                    return value_null();
                case '-':
                    if (lv.tag == Value::TAG_INT64) return value_int(lv.int_val - rv.int_val);
                    if (lv.tag == Value::TAG_DOUBLE) return value_double(lv.double_val - rv.double_val);
                    return value_null();
                case '*':
                    if (lv.tag == Value::TAG_INT64) return value_int(lv.int_val * rv.int_val);
                    if (lv.tag == Value::TAG_DOUBLE) return value_double(lv.double_val * rv.double_val);
                    return value_null();
                case '/':
                    if (lv.tag == Value::TAG_INT64) {
                        if (rv.int_val == 0) return value_null();
                        return value_int(lv.int_val / rv.int_val);
                    }
                    if (lv.tag == Value::TAG_DOUBLE) {
                        if (rv.double_val == 0.0) return value_null();
                        return value_double(lv.double_val / rv.double_val);
                    }
                    return value_null();
                case '%':
                    if (lv.tag == Value::TAG_INT64) {
                        if (rv.int_val == 0) return value_null();
                        return value_int(lv.int_val % rv.int_val);
                    }
                    if (lv.tag == Value::TAG_DOUBLE) {
                        if (rv.double_val == 0.0) return value_null();
                        return value_double(std::fmod(lv.double_val, rv.double_val));
                    }
                    return value_null();
                default:
                    break;
            }
        }

        // --- Comparison operators ---
        // =
        if (op.len == 1 && op.ptr[0] == '=') {
            if (lv.tag == Value::TAG_INT64)  return value_bool(lv.int_val == rv.int_val);
            if (lv.tag == Value::TAG_DOUBLE) return value_bool(lv.double_val == rv.double_val);
            if (lv.tag == Value::TAG_STRING) return value_bool(lv.str_val == rv.str_val);
            if (lv.tag == Value::TAG_BOOL)   return value_bool(lv.bool_val == rv.bool_val);
            return value_null();
        }
        // <> or !=
        if ((op.len == 2 && op.ptr[0] == '<' && op.ptr[1] == '>') ||
            (op.len == 2 && op.ptr[0] == '!' && op.ptr[1] == '=')) {
            if (lv.tag == Value::TAG_INT64)  return value_bool(lv.int_val != rv.int_val);
            if (lv.tag == Value::TAG_DOUBLE) return value_bool(lv.double_val != rv.double_val);
            if (lv.tag == Value::TAG_STRING) return value_bool(lv.str_val != rv.str_val);
            if (lv.tag == Value::TAG_BOOL)   return value_bool(lv.bool_val != rv.bool_val);
            return value_null();
        }
        // <
        if (op.len == 1 && op.ptr[0] == '<') {
            if (lv.tag == Value::TAG_INT64)  return value_bool(lv.int_val < rv.int_val);
            if (lv.tag == Value::TAG_DOUBLE) return value_bool(lv.double_val < rv.double_val);
            if (lv.tag == Value::TAG_STRING) {
                int cmp = std::memcmp(lv.str_val.ptr, rv.str_val.ptr,
                    lv.str_val.len < rv.str_val.len ? lv.str_val.len : rv.str_val.len);
                if (cmp == 0) return value_bool(lv.str_val.len < rv.str_val.len);
                return value_bool(cmp < 0);
            }
            return value_null();
        }
        // >
        if (op.len == 1 && op.ptr[0] == '>') {
            if (lv.tag == Value::TAG_INT64)  return value_bool(lv.int_val > rv.int_val);
            if (lv.tag == Value::TAG_DOUBLE) return value_bool(lv.double_val > rv.double_val);
            if (lv.tag == Value::TAG_STRING) {
                int cmp = std::memcmp(lv.str_val.ptr, rv.str_val.ptr,
                    lv.str_val.len < rv.str_val.len ? lv.str_val.len : rv.str_val.len);
                if (cmp == 0) return value_bool(lv.str_val.len > rv.str_val.len);
                return value_bool(cmp > 0);
            }
            return value_null();
        }
        // <=
        if (op.len == 2 && op.ptr[0] == '<' && op.ptr[1] == '=') {
            if (lv.tag == Value::TAG_INT64)  return value_bool(lv.int_val <= rv.int_val);
            if (lv.tag == Value::TAG_DOUBLE) return value_bool(lv.double_val <= rv.double_val);
            if (lv.tag == Value::TAG_STRING) {
                int cmp = std::memcmp(lv.str_val.ptr, rv.str_val.ptr,
                    lv.str_val.len < rv.str_val.len ? lv.str_val.len : rv.str_val.len);
                if (cmp == 0) return value_bool(lv.str_val.len <= rv.str_val.len);
                return value_bool(cmp < 0);
            }
            return value_null();
        }
        // >=
        if (op.len == 2 && op.ptr[0] == '>' && op.ptr[1] == '=') {
            if (lv.tag == Value::TAG_INT64)  return value_bool(lv.int_val >= rv.int_val);
            if (lv.tag == Value::TAG_DOUBLE) return value_bool(lv.double_val >= rv.double_val);
            if (lv.tag == Value::TAG_STRING) {
                int cmp = std::memcmp(lv.str_val.ptr, rv.str_val.ptr,
                    lv.str_val.len < rv.str_val.len ? lv.str_val.len : rv.str_val.len);
                if (cmp == 0) return value_bool(lv.str_val.len >= rv.str_val.len);
                return value_bool(cmp >= 0);
            }
            return value_null();
        }

        return value_null();  // unknown operator
    }

    // ---- IS NULL / IS NOT NULL (never return NULL) ----

    case NodeType::NODE_IS_NULL: {
        Value child = evaluate_expression<D>(expr->first_child, resolve, functions, arena, subquery_exec);
        return value_bool(child.is_null());
    }

    case NodeType::NODE_IS_NOT_NULL: {
        Value child = evaluate_expression<D>(expr->first_child, resolve, functions, arena, subquery_exec);
        return value_bool(!child.is_null());
    }

    // ---- BETWEEN: expr >= low AND expr <= high ----

    case NodeType::NODE_BETWEEN: {
        const AstNode* expr_node = detail::nth_child(expr, 0);
        const AstNode* low_node  = detail::nth_child(expr, 1);
        const AstNode* high_node = detail::nth_child(expr, 2);
        if (!expr_node || !low_node || !high_node) return value_null();

        Value val  = evaluate_expression<D>(expr_node, resolve, functions, arena, subquery_exec);
        Value low  = evaluate_expression<D>(low_node,  resolve, functions, arena);
        Value high = evaluate_expression<D>(high_node, resolve, functions, arena, subquery_exec);

        // NULL propagation
        if (val.is_null() || low.is_null() || high.is_null()) return value_null();

        // Coerce all three to common type
        SqlType::Kind k1 = tag_to_kind(val.tag);
        SqlType::Kind k2 = tag_to_kind(low.tag);
        SqlType::Kind k3 = tag_to_kind(high.tag);
        SqlType::Kind common = CoercionRules<D>::common_type(
            CoercionRules<D>::common_type(k1, k2), k3);
        if (common == SqlType::UNKNOWN) return value_null();
        Value::Tag target = kind_to_tag(common);

        Value v = CoercionRules<D>::coerce_value(val,  target, arena);
        Value l = CoercionRules<D>::coerce_value(low,  target, arena);
        Value h = CoercionRules<D>::coerce_value(high, target, arena);
        if (v.is_null() || l.is_null() || h.is_null()) return value_null();

        // Compare: v >= l AND v <= h
        bool ge = false, le = false;
        if (v.tag == Value::TAG_INT64) {
            ge = v.int_val >= l.int_val;
            le = v.int_val <= h.int_val;
        } else if (v.tag == Value::TAG_DOUBLE) {
            ge = v.double_val >= l.double_val;
            le = v.double_val <= h.double_val;
        } else if (v.tag == Value::TAG_STRING) {
            auto scmp = [](StringRef a, StringRef b) -> int {
                uint32_t minlen = a.len < b.len ? a.len : b.len;
                int r = std::memcmp(a.ptr, b.ptr, minlen);
                if (r != 0) return r;
                return (a.len < b.len) ? -1 : (a.len > b.len) ? 1 : 0;
            };
            ge = scmp(v.str_val, l.str_val) >= 0;
            le = scmp(v.str_val, h.str_val) <= 0;
        } else {
            return value_null();
        }
        return value_bool(ge && le);
    }

    // ---- IN list ----

    case NodeType::NODE_IN_LIST: {
        const AstNode* expr_node = expr->first_child;
        if (!expr_node) return value_null();

        Value val = evaluate_expression<D>(expr_node, resolve, functions, arena, subquery_exec);
        if (val.is_null()) return value_null();

        bool found = false;
        bool has_null = false;

        // Collect all IN-list values. If a child is a subquery, expand it.
        std::vector<Value> in_values;
        for (const AstNode* item = expr_node->next_sibling; item; item = item->next_sibling) {
            if (item->type == NodeType::NODE_SUBQUERY && subquery_exec && item->first_child) {
                // IN (subquery) -- execute and expand
                std::vector<Value> set_vals = subquery_exec->execute_set(item, resolve);
                for (auto& sv : set_vals) in_values.push_back(sv);
            } else {
                in_values.push_back(evaluate_expression<D>(item, resolve, functions, arena, subquery_exec));
            }
        }

        for (const auto& item_val : in_values) {
            if (item_val.is_null()) {
                has_null = true;
                continue;
            }
            // Coerce and compare
            SqlType::Kind lk = tag_to_kind(val.tag);
            SqlType::Kind rk = tag_to_kind(item_val.tag);
            SqlType::Kind common = CoercionRules<D>::common_type(lk, rk);
            if (common == SqlType::UNKNOWN) continue;
            Value::Tag target = kind_to_tag(common);
            Value lv = CoercionRules<D>::coerce_value(val,      target, arena);
            Value rv = CoercionRules<D>::coerce_value(item_val, target, arena);
            if (lv.is_null() || rv.is_null()) { has_null = true; continue; }

            bool eq = false;
            if (lv.tag == Value::TAG_INT64)  eq = lv.int_val == rv.int_val;
            else if (lv.tag == Value::TAG_DOUBLE) eq = lv.double_val == rv.double_val;
            else if (lv.tag == Value::TAG_STRING) eq = lv.str_val == rv.str_val;
            else if (lv.tag == Value::TAG_BOOL) eq = lv.bool_val == rv.bool_val;

            if (eq) { found = true; break; }
        }

        if (found) return value_bool(true);
        if (has_null) return value_null();
        return value_bool(false);
    }

    // ---- CASE/WHEN ----

    case NodeType::NODE_CASE_WHEN: {
        uint32_t count = detail::child_count(expr);
        bool is_simple = (expr->flags == 1);

        if (is_simple) {
            // Simple CASE: children = [case_expr, when1, then1, when2, then2, ..., else?]
            const AstNode* case_node = expr->first_child;
            if (!case_node) return value_null();
            Value case_val = evaluate_expression<D>(case_node, resolve, functions, arena, subquery_exec);

            const AstNode* child = case_node->next_sibling;
            uint32_t remaining = count - 1;  // excluding case_expr

            while (child && child->next_sibling) {
                Value when_val = evaluate_expression<D>(child, resolve, functions, arena, subquery_exec);
                const AstNode* then_node = child->next_sibling;

                // Compare case_val = when_val
                bool match = false;
                if (!case_val.is_null() && !when_val.is_null()) {
                    SqlType::Kind lk = tag_to_kind(case_val.tag);
                    SqlType::Kind rk = tag_to_kind(when_val.tag);
                    SqlType::Kind common = CoercionRules<D>::common_type(lk, rk);
                    if (common != SqlType::UNKNOWN) {
                        Value::Tag target = kind_to_tag(common);
                        Value lv = CoercionRules<D>::coerce_value(case_val, target, arena);
                        Value rv = CoercionRules<D>::coerce_value(when_val, target, arena);
                        if (!lv.is_null() && !rv.is_null()) {
                            if (lv.tag == Value::TAG_INT64)  match = lv.int_val == rv.int_val;
                            else if (lv.tag == Value::TAG_DOUBLE) match = lv.double_val == rv.double_val;
                            else if (lv.tag == Value::TAG_STRING) match = lv.str_val == rv.str_val;
                            else if (lv.tag == Value::TAG_BOOL)   match = lv.bool_val == rv.bool_val;
                        }
                    }
                }

                if (match) {
                    return evaluate_expression<D>(then_node, resolve, functions, arena, subquery_exec);
                }

                child = then_node->next_sibling;
                remaining -= 2;
            }

            // Check for ELSE (one remaining child)
            if (child && remaining == 1) {
                return evaluate_expression<D>(child, resolve, functions, arena, subquery_exec);
            }
            return value_null();
        } else {
            // Searched CASE: children = [when1, then1, when2, then2, ..., else?]
            const AstNode* child = expr->first_child;
            uint32_t remaining = count;

            while (child && child->next_sibling) {
                Value when_val = evaluate_expression<D>(child, resolve, functions, arena, subquery_exec);
                const AstNode* then_node = child->next_sibling;

                // Evaluate WHEN condition as boolean
                bool is_true = false;
                if (!when_val.is_null()) {
                    if (when_val.tag == Value::TAG_BOOL) is_true = when_val.bool_val;
                    else if (when_val.tag == Value::TAG_INT64) is_true = when_val.int_val != 0;
                    else if (when_val.tag == Value::TAG_DOUBLE) is_true = when_val.double_val != 0.0;
                    else is_true = true;  // non-null non-numeric = truthy
                }

                if (is_true) {
                    return evaluate_expression<D>(then_node, resolve, functions, arena, subquery_exec);
                }

                child = then_node->next_sibling;
                remaining -= 2;
            }

            // Check for ELSE (one remaining child)
            if (child && remaining % 2 == 1) {
                return evaluate_expression<D>(child, resolve, functions, arena, subquery_exec);
            }
            return value_null();
        }
    }

    // ---- Function calls ----

    case NodeType::NODE_FUNCTION_CALL: {
        StringRef name = expr->value();
        const FunctionEntry* entry = functions.lookup(name.ptr, name.len);
        if (!entry) return value_null();

        // Evaluate arguments into a stack buffer
        constexpr uint32_t MAX_ARGS = 64;
        // Use aligned storage to avoid Value default-construction issues
        alignas(Value) char args_storage[MAX_ARGS * sizeof(Value)];
        Value* args = reinterpret_cast<Value*>(args_storage);
        uint32_t i = 0;
        for (const AstNode* arg = expr->first_child; arg && i < MAX_ARGS;
             arg = arg->next_sibling, ++i) {
            new (&args[i]) Value(evaluate_expression<D>(arg, resolve, functions, arena, subquery_exec));
        }
        return entry->impl(args, static_cast<uint16_t>(i), arena);
    }

    // ---- Deferred node types (return value_null) ----

    case NodeType::NODE_SUBQUERY: {
        // If the subquery has a parsed SELECT child and we have an executor, run it
        if (subquery_exec && expr->first_child) {
            // Check if this is an EXISTS subquery (flags == 1)
            if (expr->flags == 1) {
                bool exists = subquery_exec->execute_exists(expr, resolve);
                return value_bool(exists);
            }
            // Otherwise treat as scalar subquery
            return subquery_exec->execute_scalar(expr, resolve);
        }
        return value_null();  // no executor or no parsed child
    }
    case NodeType::NODE_TUPLE:
    case NodeType::NODE_ARRAY_CONSTRUCTOR: {
        // Evaluate each child into a compound runtime value. NODE_TUPLE
        // produces TAG_TUPLE; NODE_ARRAY_CONSTRUCTOR produces TAG_ARRAY.
        // Empty constructor is represented as a zero-element compound,
        // not NULL — so downstream subscript / field access can still
        // observe the empty container shape.
        uint32_t count = 0;
        for (const AstNode* c = expr->first_child; c; c = c->next_sibling) ++count;
        Value* elems = static_cast<Value*>(arena.allocate(sizeof(Value) * (count ? count : 1)));
        uint32_t i = 0;
        for (const AstNode* c = expr->first_child; c; c = c->next_sibling, ++i) {
            elems[i] = evaluate_expression<D>(c, resolve, functions, arena, subquery_exec);
        }
        return (expr->type == NodeType::NODE_ARRAY_CONSTRUCTOR)
            ? value_array(arena, elems, count)
            : value_tuple(arena, elems, count);
    }
    case NodeType::NODE_ARRAY_SUBSCRIPT: {
        const AstNode* array_expr = expr->first_child;
        const AstNode* index_expr = array_expr ? array_expr->next_sibling : nullptr;
        if (!array_expr || !index_expr) return value_null();

        Value idx = evaluate_expression<D>(index_expr, resolve, functions, arena, subquery_exec);
        if (idx.is_null()) return value_null();
        int64_t i = idx.to_int64();

        // Evaluate the array side (works for literal AST arrays via the
        // case above and for resolver-returned runtime arrays alike).
        Value arr = evaluate_expression<D>(array_expr, resolve, functions, arena, subquery_exec);
        if (arr.tag != Value::TAG_ARRAY || !arr.compound_val) return value_null();

        // 1-based indexing for PostgreSQL, 0-based for MySQL.
        int64_t pos = (D == sql_parser::Dialect::PostgreSQL) ? i - 1 : i;
        if (pos < 0 || static_cast<uint32_t>(pos) >= arr.compound_val->count)
            return value_null();
        return arr.compound_val->elements[static_cast<uint32_t>(pos)];
    }
    case NodeType::NODE_FIELD_ACCESS: {
        // (expr).field — evaluate the left side; if it yields a TAG_TUPLE
        // with field_names, look up by case-insensitive field name match.
        // All other shapes (unnamed tuples, non-compound values, missing
        // names) return NULL per the conservative spec semantics.
        const AstNode* lhs = expr->first_child;
        if (!lhs) return value_null();
        Value tup = evaluate_expression<D>(lhs, resolve, functions, arena, subquery_exec);
        if (tup.tag != Value::TAG_TUPLE || !tup.compound_val ||
            !tup.compound_val->field_names) return value_null();
        StringRef field = expr->value();
        if (!field.ptr || field.len == 0) return value_null();
        for (uint32_t k = 0; k < tup.compound_val->count; ++k) {
            if (tup.compound_val->field_names[k].equals_ci(field.ptr, field.len)) {
                return tup.compound_val->elements[k];
            }
        }
        return value_null();
    }

    default:
        return value_null();  // unknown node type
    }
}

} // namespace sql_engine

#endif // SQL_ENGINE_EXPRESSION_EVAL_H
