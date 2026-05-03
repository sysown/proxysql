// constant_folding.h — Evaluate sub-expressions that have no column references
// at plan time, replacing them with literal AST nodes.
//
// Walks all expression ASTs in Filter, Project, Sort conditions. For each
// sub-expression with zero column references, evaluates it using
// evaluate_expression with a null resolver and replaces the node in-place.

#ifndef SQL_ENGINE_RULES_CONSTANT_FOLDING_H
#define SQL_ENGINE_RULES_CONSTANT_FOLDING_H

#include "sql_engine/plan_node.h"
#include "sql_engine/catalog.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/function_registry.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/common.h"
#include <cstdio>
#include <cstring>

namespace sql_engine {
namespace rules {

namespace detail_cf {

// Check if a function name is an aggregate function
inline bool is_aggregate_function(const sql_parser::AstNode* expr) {
    if (!expr || expr->type != sql_parser::NodeType::NODE_FUNCTION_CALL) return false;
    sql_parser::StringRef name = expr->value();
    return name.equals_ci("COUNT", 5) || name.equals_ci("SUM", 3) ||
           name.equals_ci("AVG", 3) || name.equals_ci("MIN", 3) ||
           name.equals_ci("MAX", 3);
}

// Check if an expression has any column references or aggregate functions
// (aggregate functions depend on row data and must not be folded)
inline bool has_column_ref(const sql_parser::AstNode* expr) {
    if (!expr) return false;
    switch (expr->type) {
        case sql_parser::NodeType::NODE_COLUMN_REF:
        case sql_parser::NodeType::NODE_QUALIFIED_NAME:
            return true;
        case sql_parser::NodeType::NODE_IDENTIFIER:
            // Identifiers in expression context are column references
            return true;
        case sql_parser::NodeType::NODE_FUNCTION_CALL:
            // Aggregate functions depend on row data, not foldable
            if (is_aggregate_function(expr)) return true;
            break;
        default:
            break;
    }
    for (const sql_parser::AstNode* c = expr->first_child; c; c = c->next_sibling) {
        if (has_column_ref(c)) return true;
    }
    return false;
}

// Try to fold a constant sub-expression. Returns true if folded.
// Modifies the node in-place (arena-allocated, safe to mutate).
template <sql_parser::Dialect D>
inline bool try_fold(sql_parser::AstNode* expr,
                     FunctionRegistry<D>& functions,
                     sql_parser::Arena& arena) {
    if (!expr) return false;

    // Don't fold leaf literals — already constant
    switch (expr->type) {
        case sql_parser::NodeType::NODE_LITERAL_INT:
        case sql_parser::NodeType::NODE_LITERAL_FLOAT:
        case sql_parser::NodeType::NODE_LITERAL_STRING:
        case sql_parser::NodeType::NODE_LITERAL_NULL:
            return false;
        default:
            break;
    }

    // If this expression has no column refs, try to evaluate it
    if (!has_column_ref(expr)) {
        // Null resolver — any column reference attempt returns null
        auto null_resolve = [](sql_parser::StringRef) -> Value {
            return value_null();
        };

        Value result = evaluate_expression<D>(expr, null_resolve, functions, arena);

        if (result.is_null()) {
            expr->type = sql_parser::NodeType::NODE_LITERAL_NULL;
            expr->first_child = nullptr;
            expr->value_ptr = nullptr;
            expr->value_len = 0;
            return true;
        }

        // Replace node with appropriate literal type
        switch (result.tag) {
            case Value::TAG_INT64: {
                // Format integer as string in arena
                char tmp[32];
                int n = std::snprintf(tmp, sizeof(tmp), "%lld",
                                      static_cast<long long>(result.int_val));
                if (n > 0) {
                    char* buf = static_cast<char*>(arena.allocate(static_cast<uint32_t>(n)));
                    std::memcpy(buf, tmp, static_cast<size_t>(n));
                    expr->type = sql_parser::NodeType::NODE_LITERAL_INT;
                    expr->value_ptr = buf;
                    expr->value_len = static_cast<uint32_t>(n);
                    expr->first_child = nullptr;
                    return true;
                }
                break;
            }
            case Value::TAG_DOUBLE: {
                char tmp[64];
                int n = std::snprintf(tmp, sizeof(tmp), "%g", result.double_val);
                if (n > 0) {
                    char* buf = static_cast<char*>(arena.allocate(static_cast<uint32_t>(n)));
                    std::memcpy(buf, tmp, static_cast<size_t>(n));
                    expr->type = sql_parser::NodeType::NODE_LITERAL_FLOAT;
                    expr->value_ptr = buf;
                    expr->value_len = static_cast<uint32_t>(n);
                    expr->first_child = nullptr;
                    return true;
                }
                break;
            }
            case Value::TAG_STRING: {
                expr->type = sql_parser::NodeType::NODE_LITERAL_STRING;
                expr->value_ptr = result.str_val.ptr;
                expr->value_len = result.str_val.len;
                expr->first_child = nullptr;
                return true;
            }
            case Value::TAG_BOOL: {
                const char* s = result.bool_val ? "TRUE" : "FALSE";
                uint32_t len = result.bool_val ? 4 : 5;
                char* buf = static_cast<char*>(arena.allocate(len));
                std::memcpy(buf, s, len);
                expr->type = sql_parser::NodeType::NODE_LITERAL_INT;
                expr->value_ptr = buf;
                expr->value_len = len;
                expr->first_child = nullptr;
                return true;
            }
            default:
                break;
        }
        return false;
    }

    // Has column refs — try to fold children (partial folding)
    bool any_folded = false;
    for (sql_parser::AstNode* c = expr->first_child; c; c = c->next_sibling) {
        if (try_fold<D>(c, functions, arena)) {
            any_folded = true;
        }
    }
    return any_folded;
}

// Fold all expressions in a plan node
template <sql_parser::Dialect D>
inline void fold_plan_exprs(PlanNode* node,
                            FunctionRegistry<D>& functions,
                            sql_parser::Arena& arena) {
    if (!node) return;

    switch (node->type) {
        case PlanNodeType::FILTER:
            if (node->filter.expr) {
                try_fold<D>(const_cast<sql_parser::AstNode*>(node->filter.expr),
                           functions, arena);
            }
            break;
        case PlanNodeType::PROJECT:
            for (uint16_t i = 0; i < node->project.count; ++i) {
                if (node->project.exprs[i]) {
                    try_fold<D>(const_cast<sql_parser::AstNode*>(node->project.exprs[i]),
                               functions, arena);
                }
            }
            break;
        case PlanNodeType::SORT:
            for (uint16_t i = 0; i < node->sort.count; ++i) {
                if (node->sort.keys[i]) {
                    try_fold<D>(const_cast<sql_parser::AstNode*>(node->sort.keys[i]),
                               functions, arena);
                }
            }
            break;
        case PlanNodeType::JOIN:
            if (node->join.condition) {
                try_fold<D>(const_cast<sql_parser::AstNode*>(node->join.condition),
                           functions, arena);
            }
            break;
        case PlanNodeType::AGGREGATE:
            for (uint16_t i = 0; i < node->aggregate.group_count; ++i) {
                if (node->aggregate.group_by[i]) {
                    try_fold<D>(const_cast<sql_parser::AstNode*>(node->aggregate.group_by[i]),
                               functions, arena);
                }
            }
            for (uint16_t i = 0; i < node->aggregate.agg_count; ++i) {
                if (node->aggregate.agg_exprs[i]) {
                    try_fold<D>(const_cast<sql_parser::AstNode*>(node->aggregate.agg_exprs[i]),
                               functions, arena);
                }
            }
            break;
        default:
            break;
    }
}

} // namespace detail_cf

template <sql_parser::Dialect D>
inline PlanNode* constant_folding(PlanNode* node, const Catalog& catalog,
                                   FunctionRegistry<D>& functions,
                                   sql_parser::Arena& arena) {
    if (!node) return nullptr;

    // Fold expressions in this node
    detail_cf::fold_plan_exprs<D>(node, functions, arena);

    // Recurse into children
    node->left = constant_folding<D>(node->left, catalog, functions, arena);
    node->right = constant_folding<D>(node->right, catalog, functions, arena);

    return node;
}

} // namespace rules
} // namespace sql_engine

#endif // SQL_ENGINE_RULES_CONSTANT_FOLDING_H
