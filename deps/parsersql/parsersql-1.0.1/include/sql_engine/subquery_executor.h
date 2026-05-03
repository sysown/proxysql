// subquery_executor.h -- Execute subqueries from within the expression evaluator
//
// SubqueryExecutor<D> bridges the expression evaluator and the full query
// execution pipeline. When evaluate_expression encounters a NODE_SUBQUERY
// that has a parsed SELECT AST child, it delegates to SubqueryExecutor to:
//   - Build a plan from the inner SELECT AST
//   - Execute the plan via PlanExecutor
//   - Return the appropriate result (scalar value, existence check, value set)
//
// For correlated subqueries, the outer row's resolver is passed through so
// the inner query can reference outer columns.

#ifndef SQL_ENGINE_SUBQUERY_EXECUTOR_H
#define SQL_ENGINE_SUBQUERY_EXECUTOR_H

#include "sql_engine/plan_node.h"
#include "sql_engine/value.h"
#include "sql_engine/result_set.h"
#include "sql_engine/row.h"
#include "sql_parser/ast.h"
#include "sql_parser/common.h"
#include "sql_parser/arena.h"
#include <functional>
#include <vector>

namespace sql_engine {

// Forward declarations -- the actual PlanBuilder and PlanExecutor are
// template classes; SubqueryExecutor stores opaque callbacks to avoid
// circular header dependencies.
//
// The callbacks are set by PlanExecutor when it wires up subquery support.

template <sql_parser::Dialect D>
class SubqueryExecutor {
public:
    // Callback types. These are set by the PlanExecutor that owns us.
    using BuildPlanFn  = std::function<PlanNode*(const sql_parser::AstNode*)>;
    using ExecutePlanFn = std::function<ResultSet(PlanNode*)>;
    // Correlated variant: accepts an outer resolver that inner operators can use
    using ExecutePlanCorrelatedFn = std::function<ResultSet(
        PlanNode*, const std::function<Value(sql_parser::StringRef)>&)>;

    SubqueryExecutor() = default;

    void set_build_plan(BuildPlanFn fn) { build_plan_ = std::move(fn); }
    void set_execute_plan(ExecutePlanFn fn) { execute_plan_ = std::move(fn); }
    void set_execute_plan_correlated(ExecutePlanCorrelatedFn fn) {
        execute_plan_correlated_ = std::move(fn);
    }

    // Execute a scalar subquery: returns the single value, or NULL if 0 rows.
    // The subquery_ast is a NODE_SUBQUERY whose first_child is a SELECT AST.
    Value execute_scalar(const sql_parser::AstNode* subquery_ast,
                         const std::function<Value(sql_parser::StringRef)>& outer_resolve) {
        ResultSet rs = run_inner(subquery_ast, outer_resolve);
        if (rs.rows.empty()) return value_null();
        // Scalar subquery must return exactly one row with one column
        if (rs.rows.size() > 1) return value_null(); // error: more than one row
        if (rs.rows[0].column_count == 0) return value_null();
        return rs.rows[0].get(0);
    }

    // Execute an EXISTS subquery: returns true if at least one row.
    bool execute_exists(const sql_parser::AstNode* subquery_ast,
                        const std::function<Value(sql_parser::StringRef)>& outer_resolve) {
        ResultSet rs = run_inner(subquery_ast, outer_resolve);
        return !rs.rows.empty();
    }

    // Execute a set subquery (for IN): returns all values from the first column.
    std::vector<Value> execute_set(const sql_parser::AstNode* subquery_ast,
                                   const std::function<Value(sql_parser::StringRef)>& outer_resolve) {
        ResultSet rs = run_inner(subquery_ast, outer_resolve);
        std::vector<Value> result;
        result.reserve(rs.rows.size());
        for (const auto& row : rs.rows) {
            if (row.column_count > 0) {
                result.push_back(row.get(0));
            }
        }
        return result;
    }

private:
    BuildPlanFn build_plan_;
    ExecutePlanFn execute_plan_;
    ExecutePlanCorrelatedFn execute_plan_correlated_;

    ResultSet run_inner(const sql_parser::AstNode* subquery_ast,
                        const std::function<Value(sql_parser::StringRef)>& outer_resolve) {
        if (!subquery_ast || !build_plan_) return {};
        // The first child of NODE_SUBQUERY is the parsed SELECT AST
        const sql_parser::AstNode* inner_ast = subquery_ast->first_child;
        if (!inner_ast) return {};

        // Use the non-correlated path first (more reliable).
        // The correlated path passes the outer resolver as a fallback
        // to the inner executor, enabling resolution of outer column references.
        // We always use the correlated path when available since it's a
        // superset (non-correlated queries will just never use the fallback).
        // However, to avoid arena/lifetime issues, try non-correlated first
        // and only use correlated if the outer_resolve is actually set.
        PlanNode* plan = build_plan_(inner_ast);
        if (!plan) return {};

        // Use correlated path when available (it's a superset of non-correlated:
        // passes the outer resolver as fallback for column resolution)
        if (execute_plan_correlated_) {
            return execute_plan_correlated_(plan, outer_resolve);
        }
        if (execute_plan_) {
            return execute_plan_(plan);
        }
        return {};
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_SUBQUERY_EXECUTOR_H
