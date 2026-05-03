// optimizer.h — Rule-based query optimizer
//
// Optimizer<D> applies three rewrite rules in sequence to transform a logical
// plan into a more efficient logical plan:
//   1. Predicate pushdown — push filters below joins
//   2. Constant folding — evaluate constant sub-expressions at plan time
//   3. Limit pushdown — push limits past filters toward scans
//
// Not included (yet): projection pruning. The Project operator already
// does column subsetting at eval time, so the main win from a pruning
// rule is inserting slimming Projects above Scans in long chains to
// reduce row size through Filters and Sorts. That's a real optimization
// but not a correctness issue and requires tracking per-operator needed-
// column sets. Left out of the pipeline rather than kept as a no-op,
// so the optimizer is honest about what it actually does.

#ifndef SQL_ENGINE_OPTIMIZER_H
#define SQL_ENGINE_OPTIMIZER_H

#include "sql_engine/plan_node.h"
#include "sql_engine/catalog.h"
#include "sql_engine/function_registry.h"
#include "sql_engine/rules/predicate_pushdown.h"
#include "sql_engine/rules/constant_folding.h"
#include "sql_engine/rules/limit_pushdown.h"
#include "sql_parser/arena.h"
#include "sql_parser/common.h"

namespace sql_engine {

template <sql_parser::Dialect D>
class Optimizer {
public:
    Optimizer(const Catalog& catalog, FunctionRegistry<D>& functions)
        : catalog_(catalog), functions_(functions) {}

    PlanNode* optimize(PlanNode* plan, sql_parser::Arena& arena) {
        if (!plan) return nullptr;

        plan = rules::predicate_pushdown(plan, catalog_, arena);
        plan = rules::constant_folding<D>(plan, catalog_, functions_, arena);
        plan = rules::limit_pushdown(plan, catalog_, arena);

        return plan;
    }

private:
    const Catalog& catalog_;
    FunctionRegistry<D>& functions_;
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPTIMIZER_H
