// limit_pushdown.h — Push Limit nodes past Filter nodes toward Scan nodes.
//
// When we see Limit -> Filter -> child (with no Sort/Aggregate/Distinct/Join
// between), insert a new Limit node between Filter and child with the same
// count. The inner Limit is a hint for early termination.

#ifndef SQL_ENGINE_RULES_LIMIT_PUSHDOWN_H
#define SQL_ENGINE_RULES_LIMIT_PUSHDOWN_H

#include "sql_engine/plan_node.h"
#include "sql_engine/catalog.h"
#include "sql_parser/arena.h"

namespace sql_engine {
namespace rules {

inline PlanNode* limit_pushdown(PlanNode* node, const Catalog& catalog,
                                 sql_parser::Arena& arena) {
    if (!node) return nullptr;

    // Recurse into children first
    node->left = limit_pushdown(node->left, catalog, arena);
    node->right = limit_pushdown(node->right, catalog, arena);

    // Pattern: Limit -> Filter -> child
    if (node->type != PlanNodeType::LIMIT) return node;
    if (!node->left || node->left->type != PlanNodeType::FILTER) return node;

    PlanNode* filter = node->left;
    PlanNode* filter_child = filter->left;

    // Don't push if the filter's child is Sort, Aggregate, Distinct, or Join
    if (filter_child) {
        switch (filter_child->type) {
            case PlanNodeType::SORT:
            case PlanNodeType::AGGREGATE:
            case PlanNodeType::DISTINCT:
            case PlanNodeType::JOIN:
                return node; // blocked
            default:
                break;
        }
    }

    // Insert a new Limit between Filter and its child
    PlanNode* inner_limit = make_plan_node(arena, PlanNodeType::LIMIT);
    inner_limit->limit.count = node->limit.count;
    inner_limit->limit.offset = 0; // inner limit doesn't need offset
    inner_limit->left = filter_child;

    filter->left = inner_limit;

    return node;
}

} // namespace rules
} // namespace sql_engine

#endif // SQL_ENGINE_RULES_LIMIT_PUSHDOWN_H
