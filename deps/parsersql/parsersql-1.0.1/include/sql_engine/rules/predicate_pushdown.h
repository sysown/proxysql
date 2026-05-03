// predicate_pushdown.h — Push Filter nodes below Join nodes when the filter
// condition only references columns from one side of the join.
//
// For compound AND conditions, split and push each predicate independently.
// If a predicate references both sides or can't be determined, leave in place.

#ifndef SQL_ENGINE_RULES_PREDICATE_PUSHDOWN_H
#define SQL_ENGINE_RULES_PREDICATE_PUSHDOWN_H

#include "sql_engine/plan_node.h"
#include "sql_engine/catalog.h"
#include "sql_parser/ast.h"
#include "sql_parser/arena.h"
#include "sql_parser/common.h"
#include <cstring>

namespace sql_engine {
namespace rules {

// Collect all table names referenced in an expression AST.
// Walks the expression looking for NODE_QUALIFIED_NAME (table.column) and
// NODE_COLUMN_REF / NODE_IDENTIFIER (unqualified — resolved via catalog).
namespace detail_ppd {

inline void collect_expr_table_refs(const sql_parser::AstNode* expr,
                                    const Catalog& catalog,
                                    const char** out_tables,
                                    uint32_t* out_lens,
                                    uint16_t& count,
                                    uint16_t max_count) {
    if (!expr || count >= max_count) return;

    if (expr->type == sql_parser::NodeType::NODE_QUALIFIED_NAME) {
        // First child is table, second is column
        const sql_parser::AstNode* tbl = expr->first_child;
        if (tbl) {
            sql_parser::StringRef tv = tbl->value();
            // Check if already recorded
            bool found = false;
            for (uint16_t i = 0; i < count; ++i) {
                if (out_lens[i] == tv.len &&
                    std::memcmp(out_tables[i], tv.ptr, tv.len) == 0) {
                    found = true;
                    break;
                }
            }
            if (!found && count < max_count) {
                out_tables[count] = tv.ptr;
                out_lens[count] = tv.len;
                ++count;
            }
        }
        return; // Don't recurse into children of qualified name
    }

    // For unqualified column refs, we can't easily determine the table
    // without scanning all catalog tables. Skip for now (conservative:
    // if we can't determine, the predicate won't be pushed).
    // Recurse into children for compound expressions
    for (const sql_parser::AstNode* c = expr->first_child; c; c = c->next_sibling) {
        collect_expr_table_refs(c, catalog, out_tables, out_lens, count, max_count);
    }
}

// Collect all table names from a plan subtree (scan nodes)
inline void collect_plan_tables(const PlanNode* node,
                                const char** out_tables,
                                uint32_t* out_lens,
                                uint16_t& count,
                                uint16_t max_count) {
    if (!node || count >= max_count) return;
    if (node->type == PlanNodeType::SCAN && node->scan.table) {
        sql_parser::StringRef tn = node->scan.table->table_name;
        bool found = false;
        for (uint16_t i = 0; i < count; ++i) {
            if (out_lens[i] == tn.len &&
                std::memcmp(out_tables[i], tn.ptr, tn.len) == 0) {
                found = true;
                break;
            }
        }
        if (!found && count < max_count) {
            out_tables[count] = tn.ptr;
            out_lens[count] = tn.len;
            ++count;
        }
        return;
    }
    collect_plan_tables(node->left, out_tables, out_lens, count, max_count);
    collect_plan_tables(node->right, out_tables, out_lens, count, max_count);
}

// Check if all table refs in expr_tables are contained in plan_tables
inline bool all_refs_in(const char** expr_tables, uint32_t* expr_lens, uint16_t expr_count,
                        const char** plan_tables, uint32_t* plan_lens, uint16_t plan_count) {
    for (uint16_t i = 0; i < expr_count; ++i) {
        bool found = false;
        for (uint16_t j = 0; j < plan_count; ++j) {
            if (expr_lens[i] == plan_lens[j] &&
                sql_parser::StringRef{expr_tables[i], expr_lens[i]}.equals_ci(
                    plan_tables[j], plan_lens[j])) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

// Check if a binary op is AND
inline bool is_and_op(const sql_parser::AstNode* expr) {
    if (!expr) return false;
    if (expr->type != sql_parser::NodeType::NODE_BINARY_OP) return false;
    sql_parser::StringRef op = expr->value();
    return op.equals_ci("AND", 3);
}

// Collect all AND-separated predicates from an expression
inline void collect_and_predicates(const sql_parser::AstNode* expr,
                                   const sql_parser::AstNode** out,
                                   uint16_t& count,
                                   uint16_t max_count) {
    if (!expr || count >= max_count) return;
    if (is_and_op(expr)) {
        // Recurse into left and right children
        const sql_parser::AstNode* left = expr->first_child;
        const sql_parser::AstNode* right = left ? left->next_sibling : nullptr;
        collect_and_predicates(left, out, count, max_count);
        collect_and_predicates(right, out, count, max_count);
    } else {
        out[count++] = expr;
    }
}

// Build an AND expression from multiple predicates
inline const sql_parser::AstNode* build_and_chain(const sql_parser::AstNode** preds,
                                                   uint16_t count,
                                                   sql_parser::Arena& arena) {
    if (count == 0) return nullptr;
    if (count == 1) return preds[0];

    // Build left-associative chain: ((p0 AND p1) AND p2) ...
    sql_parser::AstNode* result = sql_parser::make_node(
        arena, sql_parser::NodeType::NODE_BINARY_OP,
        sql_parser::StringRef{"AND", 3});
    // Cast away const for tree building — these are arena-allocated
    result->first_child = const_cast<sql_parser::AstNode*>(preds[0]);
    // Detach next_sibling from first pred to avoid corrupting original tree
    // We need to make copies of children links
    sql_parser::AstNode* left_copy = sql_parser::make_node(
        arena, preds[0]->type, preds[0]->value(), preds[0]->flags);
    left_copy->first_child = preds[0]->first_child;
    sql_parser::AstNode* right_copy = sql_parser::make_node(
        arena, preds[1]->type, preds[1]->value(), preds[1]->flags);
    right_copy->first_child = preds[1]->first_child;

    result->first_child = left_copy;
    left_copy->next_sibling = right_copy;
    right_copy->next_sibling = nullptr;

    for (uint16_t i = 2; i < count; ++i) {
        sql_parser::AstNode* new_and = sql_parser::make_node(
            arena, sql_parser::NodeType::NODE_BINARY_OP,
            sql_parser::StringRef{"AND", 3});
        sql_parser::AstNode* pred_copy = sql_parser::make_node(
            arena, preds[i]->type, preds[i]->value(), preds[i]->flags);
        pred_copy->first_child = preds[i]->first_child;
        pred_copy->next_sibling = nullptr;

        new_and->first_child = result;
        result->next_sibling = pred_copy;
        result = new_and;
    }
    return result;
}

} // namespace detail_ppd

inline PlanNode* predicate_pushdown(PlanNode* node, const Catalog& catalog,
                                     sql_parser::Arena& arena) {
    if (!node) return nullptr;

    // Recurse first (bottom-up is fine, but we process top-down for the filter-above-join pattern)
    node->left = predicate_pushdown(node->left, catalog, arena);
    node->right = predicate_pushdown(node->right, catalog, arena);

    // Pattern: Filter above Join
    if (node->type != PlanNodeType::FILTER) return node;
    if (!node->left || node->left->type != PlanNodeType::JOIN) return node;

    PlanNode* join = node->left;
    const sql_parser::AstNode* filter_expr = node->filter.expr;
    if (!filter_expr) return node;

    // Collect tables from left and right sides of join
    constexpr uint16_t MAX_TABLES = 16;
    const char* left_tables[MAX_TABLES]; uint32_t left_lens[MAX_TABLES]; uint16_t left_count = 0;
    const char* right_tables[MAX_TABLES]; uint32_t right_lens[MAX_TABLES]; uint16_t right_count = 0;

    detail_ppd::collect_plan_tables(join->left, left_tables, left_lens, left_count, MAX_TABLES);
    detail_ppd::collect_plan_tables(join->right, right_tables, right_lens, right_count, MAX_TABLES);

    // Split filter into AND-separated predicates
    constexpr uint16_t MAX_PREDS = 32;
    const sql_parser::AstNode* predicates[MAX_PREDS];
    uint16_t pred_count = 0;
    detail_ppd::collect_and_predicates(filter_expr, predicates, pred_count, MAX_PREDS);

    // Classify each predicate
    const sql_parser::AstNode* left_preds[MAX_PREDS];  uint16_t lp_count = 0;
    const sql_parser::AstNode* right_preds[MAX_PREDS]; uint16_t rp_count = 0;
    const sql_parser::AstNode* stay_preds[MAX_PREDS];  uint16_t sp_count = 0;

    for (uint16_t i = 0; i < pred_count; ++i) {
        const char* expr_tables[MAX_TABLES]; uint32_t expr_lens[MAX_TABLES]; uint16_t expr_count = 0;
        detail_ppd::collect_expr_table_refs(predicates[i], catalog,
                                            expr_tables, expr_lens, expr_count, MAX_TABLES);

        if (expr_count == 0) {
            // No qualified refs — can't determine side, leave in place
            stay_preds[sp_count++] = predicates[i];
        } else {
            bool fits_left = detail_ppd::all_refs_in(expr_tables, expr_lens, expr_count,
                                                      left_tables, left_lens, left_count);
            bool fits_right = detail_ppd::all_refs_in(expr_tables, expr_lens, expr_count,
                                                       right_tables, right_lens, right_count);
            if (fits_left && !fits_right) {
                left_preds[lp_count++] = predicates[i];
            } else if (fits_right && !fits_left) {
                right_preds[rp_count++] = predicates[i];
            } else {
                stay_preds[sp_count++] = predicates[i];
            }
        }
    }

    // If nothing to push, return unchanged
    if (lp_count == 0 && rp_count == 0) return node;

    // Push predicates to left side
    if (lp_count > 0) {
        PlanNode* lf = make_plan_node(arena, PlanNodeType::FILTER);
        lf->filter.expr = detail_ppd::build_and_chain(left_preds, lp_count, arena);
        lf->left = join->left;
        join->left = lf;
    }

    // Push predicates to right side
    if (rp_count > 0) {
        PlanNode* rf = make_plan_node(arena, PlanNodeType::FILTER);
        rf->filter.expr = detail_ppd::build_and_chain(right_preds, rp_count, arena);
        rf->left = join->right;
        join->right = rf;
    }

    // If all predicates were pushed, remove the filter node entirely
    if (sp_count == 0) {
        return join;
    }

    // Otherwise, rebuild the remaining filter
    node->filter.expr = detail_ppd::build_and_chain(stay_preds, sp_count, arena);
    return node;
}

} // namespace rules
} // namespace sql_engine

#endif // SQL_ENGINE_RULES_PREDICATE_PUSHDOWN_H
