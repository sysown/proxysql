// plan_executor.h — End-to-end query execution engine
//
// PlanExecutor<D> converts a PlanNode tree (built by PlanBuilder) into a
// Volcano-model operator tree and pulls rows through it to produce a
// ResultSet.
//
// Usage:
//   1. Construct with FunctionRegistry, Catalog, and Arena
//   2. Register data sources via add_data_source("table_name", source_ptr)
//   3. Call execute(plan) to get a ResultSet
//
// Internally, execute() does:
//   - Preprocess: push aggregate expressions from PROJECT into AGGREGATE
//   - Build operator tree: recursively convert PlanNode → Operator
//   - Pull rows: open() → next() loop → close()
//   - Populate column names from plan metadata
//
// Supports all 9 operator types: Scan, Filter, Project, NestedLoopJoin,
// Aggregate, Sort, Limit, Distinct, SetOp.

#ifndef SQL_ENGINE_PLAN_EXECUTOR_H
#define SQL_ENGINE_PLAN_EXECUTOR_H

#include "sql_engine/plan_node.h"
#include "sql_engine/plan_builder.h"
#include "sql_engine/operator.h"
#include "sql_engine/data_source.h"
#include "sql_engine/result_set.h"
#include "sql_engine/catalog.h"
#include "sql_engine/function_registry.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/operators/scan_op.h"
#include "sql_engine/operators/filter_op.h"
#include "sql_engine/operators/project_op.h"
#include "sql_engine/operators/join_op.h"
#include "sql_engine/operators/aggregate_op.h"
#include "sql_engine/operators/sort_op.h"
#include "sql_engine/operators/limit_op.h"
#include "sql_engine/operators/distinct_op.h"
#include "sql_engine/operators/set_op_op.h"
#include "sql_engine/operators/derived_scan_op.h"
#include "sql_engine/operators/remote_scan_op.h"
#include "sql_engine/operators/hash_join_op.h"
#include "sql_engine/subquery_executor.h"
#include "sql_engine/operators/merge_aggregate_op.h"
#include "sql_engine/operators/merge_sort_op.h"
#include "sql_engine/operators/window_op.h"
#include "sql_engine/remote_executor.h"
#include "sql_engine/thread_pool.h"
#include "sql_engine/dml_result.h"
#include "sql_engine/mutable_data_source.h"
#include "sql_engine/catalog_resolver.h"
#include "sql_parser/emitter.h"

#include <unordered_map>
#include <string>
#include <vector>
#include <memory>

namespace sql_engine {

template <sql_parser::Dialect D>
class PlanExecutor {
public:
    PlanExecutor(FunctionRegistry<D>& functions,
                 const Catalog& catalog,
                 sql_parser::Arena& arena)
        : functions_(functions), catalog_(catalog), arena_(arena) {}

    void add_data_source(const char* table_name, DataSource* source) {
        sources_[table_name] = source;
    }

    void add_mutable_data_source(const char* table_name, MutableDataSource* source) {
        mutable_sources_[table_name] = source;
        // Also register as a regular data source for reads
        sources_[table_name] = source;
    }

    void set_remote_executor(RemoteExecutor* exec) {
        remote_executor_ = exec;
    }

    // Enable parallel opening of RemoteScan children in merge/set operators.
    // Only safe when the RemoteExecutor is thread-safe (e.g. ThreadSafeMultiRemoteExecutor
    // with connection pooling). Disabled by default for backward compatibility.
    void set_parallel_open(bool enabled) {
        parallel_open_enabled_ = enabled;
    }

    // Set a thread pool for lightweight parallel dispatch in merge/set operators.
    // The pool must outlive this executor.
    void set_thread_pool(ThreadPool* pool) {
        pool_ = pool;
    }

    // Access the subquery executor (for operators that need it)
    SubqueryExecutor<D>* subquery_executor() { return &subquery_exec_; }

    // Set a distribute callback for subquery plans (used by Session to inject
    // distributed planning into subquery execution).
    using DistributeFn = std::function<PlanNode*(PlanNode*)>;
    void set_distribute_fn(DistributeFn fn) { distribute_fn_ = std::move(fn); }

    // Execute a query that may be wrapped in a CTE (WITH clause).
    // Takes the AST root and handles CTE materialization before building/executing the plan.
    ResultSet execute_with_cte(const sql_parser::AstNode* ast) {
        if (!ast) return {};

        if (ast->type != sql_parser::NodeType::NODE_CTE) {
            // Not a CTE, build plan normally
            PlanBuilder<D> builder(catalog_, arena_);
            PlanNode* plan = builder.build(ast);
            if (plan && distribute_fn_) plan = distribute_fn_(plan);
            return execute(plan);
        }

        // Materialize each CTE definition
        std::vector<std::unique_ptr<InMemoryDataSource>> cte_sources;
        for (const sql_parser::AstNode* child = ast->first_child; child; child = child->next_sibling) {
            if (child->type != sql_parser::NodeType::NODE_CTE_DEFINITION) continue;

            sql_parser::StringRef cte_name = child->value();
            const sql_parser::AstNode* inner_select = child->first_child;
            if (!inner_select) continue;

            // Build and execute the CTE query
            PlanBuilder<D> cte_builder(catalog_, arena_);
            PlanNode* cte_plan = cte_builder.build(inner_select);
            if (!cte_plan) continue;
            // Apply distributed planning to the CTE definition's inner
            // SELECT so a CTE that scans a sharded table still materialises
            // correctly. The materialised CTE rows live locally afterwards.
            if (distribute_fn_) cte_plan = distribute_fn_(cte_plan);

            ResultSet cte_rs = execute(cte_plan);

            // Create a synthetic TableInfo for the CTE
            uint16_t col_count = cte_rs.column_count;
            if (col_count == 0 && !cte_rs.rows.empty()) {
                col_count = cte_rs.rows[0].column_count;
            }

            // Try to get column names from the original SELECT's aliases
            // This handles cases like SELECT dept, COUNT(*) AS cnt
            std::vector<std::string> final_col_names;
            const sql_parser::AstNode* inner_items = nullptr;
            if (inner_select->type == sql_parser::NodeType::NODE_SELECT_STMT) {
                for (const sql_parser::AstNode* c = inner_select->first_child; c; c = c->next_sibling) {
                    if (c->type == sql_parser::NodeType::NODE_SELECT_ITEM_LIST) {
                        inner_items = c;
                        break;
                    }
                }
            }
            if (inner_items) {
                uint16_t idx = 0;
                for (const sql_parser::AstNode* item = inner_items->first_child;
                     item && idx < col_count; item = item->next_sibling, ++idx) {
                    // Check for alias
                    const sql_parser::AstNode* alias_node = nullptr;
                    for (const sql_parser::AstNode* c = item->first_child; c; c = c->next_sibling) {
                        if (c->type == sql_parser::NodeType::NODE_ALIAS) {
                            alias_node = c;
                            break;
                        }
                    }
                    if (alias_node) {
                        sql_parser::StringRef av = alias_node->value();
                        final_col_names.emplace_back(av.ptr, av.len);
                    } else if (idx < cte_rs.column_names.size()) {
                        final_col_names.push_back(cte_rs.column_names[idx]);
                    } else {
                        final_col_names.push_back("?column?");
                    }
                }
            } else {
                for (uint16_t i = 0; i < col_count; ++i) {
                    if (i < cte_rs.column_names.size())
                        final_col_names.push_back(cte_rs.column_names[i]);
                    else
                        final_col_names.push_back("?column?");
                }
            }

            auto* cols = static_cast<ColumnInfo*>(
                arena_.allocate(sizeof(ColumnInfo) * col_count));
            for (uint16_t i = 0; i < col_count; ++i) {
                cols[i].ordinal = i;
                cols[i].nullable = true;
                cols[i].type = SqlType::make_varchar(255);
                const std::string& cn = (i < final_col_names.size()) ? final_col_names[i] : final_col_names.back();
                char* buf = static_cast<char*>(arena_.allocate(cn.size()));
                std::memcpy(buf, cn.data(), cn.size());
                cols[i].name = sql_parser::StringRef{buf, static_cast<uint32_t>(cn.size())};
            }

            auto* table_info = static_cast<TableInfo*>(arena_.allocate(sizeof(TableInfo)));
            table_info->schema_name = {};
            // Copy CTE name into arena
            char* name_buf = static_cast<char*>(arena_.allocate(cte_name.len));
            std::memcpy(name_buf, cte_name.ptr, cte_name.len);
            table_info->table_name = sql_parser::StringRef{name_buf, cte_name.len};
            table_info->columns = cols;
            table_info->column_count = col_count;
            table_info->alias = {};

            // Register in catalog
            const_cast<Catalog&>(catalog_).register_table(table_info);

            // Deep-copy rows into arena so they persist
            std::vector<Row> cte_rows;
            for (const auto& row : cte_rs.rows) {
                Row new_row = make_row(arena_, col_count);
                for (uint16_t c = 0; c < col_count && c < row.column_count; ++c) {
                    Value v = row.get(c);
                    // Deep copy string values into arena
                    if (v.tag == Value::TAG_STRING && v.str_val.ptr) {
                        char* buf = static_cast<char*>(arena_.allocate(v.str_val.len));
                        std::memcpy(buf, v.str_val.ptr, v.str_val.len);
                        v.str_val.ptr = buf;
                        v.str_val.len = v.str_val.len;
                    }
                    new_row.set(c, v);
                }
                cte_rows.push_back(new_row);
            }

            auto source = std::make_unique<InMemoryDataSource>(table_info, std::move(cte_rows));

            // Register as data source (lowercased name)
            std::string name_str(cte_name.ptr, cte_name.len);
            for (auto& c : name_str) { if (c >= 'A' && c <= 'Z') c += 32; }
            sources_[name_str] = source.get();
            cte_sources.push_back(std::move(source));
        }

        // Now build and execute the main query
        const sql_parser::AstNode* main_query = nullptr;
        for (const sql_parser::AstNode* child = ast->first_child; child; child = child->next_sibling) {
            if (child->type == sql_parser::NodeType::NODE_SELECT_STMT ||
                child->type == sql_parser::NodeType::NODE_COMPOUND_QUERY) {
                main_query = child;
            }
        }
        if (!main_query) return {};

        PlanBuilder<D> builder(catalog_, arena_);
        PlanNode* plan = builder.build(main_query);
        // The main query may itself reference sharded tables; distribute
        // it the same way Session::execute_query would for a non-CTE
        // SELECT. Materialised CTEs registered above show up as local
        // data sources, so the distributor leaves them alone.
        if (plan && distribute_fn_) plan = distribute_fn_(plan);
        ResultSet result = execute(plan);

        // CTE sources are kept alive by cte_sources until we return
        return result;
    }

    ResultSet execute(PlanNode* plan) {
        if (!plan) return {};

        operators_.clear();

        // Wire up subquery executor callbacks
        setup_subquery_executor();

        // Pre-process: push aggregate expressions from PROJECT into AGGREGATE
        preprocess_aggregates(plan);

        Operator* root = build_operator(plan);
        if (!root) return {};

        ResultSet rs;
        root->open();
        Row row{};
        while (root->next(row)) {
            rs.rows.push_back(row);
        }
        root->close();

        // Extend operator lifetimes to match the returned ResultSet.
        // PlanExecutor is typically a stack-local in Session::execute_query,
        // so without this every operator would die when the executor goes
        // out of scope -- taking with it any heap storage that the rows'
        // Value* / StringRef pointers reference. RemoteScanOperator is the
        // canonical case: its rows live inside an internal ResultSet
        // returned from a remote backend, owned by the operator. Bare
        // single-shard REMOTE_SCAN paths (e.g. SELECT COUNT(*) FROM t
        // against a one-backend "shard") have no local operator above
        // them to copy values into the executor's arena, so without
        // lifetime extension the caller sees garbage tag values rendered
        // as "?" and zero-overwritten string starts.
        for (auto& op : operators_) {
            if (op) {
                Operator* raw = op.release();
                rs.backing_lifetimes.emplace_back(
                    std::shared_ptr<void>(raw, [](void* p) {
                        delete static_cast<Operator*>(p);
                    }));
            }
        }
        operators_.clear();

        if (!rs.rows.empty()) {
            rs.column_count = rs.rows[0].column_count;
        }

        // Build column names from plan
        build_column_names(plan, rs);

        return rs;
    }

    DmlResult execute_dml(PlanNode* plan) {
        DmlResult result;
        if (!plan) {
            result.error_message = "null plan";
            return result;
        }

        switch (plan->type) {
            case PlanNodeType::INSERT_PLAN:
                return execute_insert(plan);
            case PlanNodeType::UPDATE_PLAN:
                return execute_update(plan);
            case PlanNodeType::DELETE_PLAN:
                return execute_delete(plan);
            default:
                result.error_message = "not a DML plan";
                return result;
        }
    }

private:
    FunctionRegistry<D>& functions_;
    const Catalog& catalog_;
    sql_parser::Arena& arena_;
    std::unordered_map<std::string, DataSource*> sources_;
    std::unordered_map<std::string, MutableDataSource*> mutable_sources_;
    std::vector<std::unique_ptr<Operator>> operators_;
    RemoteExecutor* remote_executor_ = nullptr;
    bool parallel_open_enabled_ = false;
    ThreadPool* pool_ = nullptr;
    DistributeFn distribute_fn_;
    SubqueryExecutor<D> subquery_exec_;
    sql_parser::Arena subquery_plan_arena_{65536, 1048576};
    std::function<Value(sql_parser::StringRef)> outer_resolver_;

    void setup_subquery_executor() {
        // Build plan callback: uses PlanBuilder with our catalog and arena.
        // If a distribute function is set (for distributed/sharded execution),
        // apply it to the plan so subqueries also go through the distributed planner.
        subquery_exec_.set_build_plan([this](const sql_parser::AstNode* ast) -> PlanNode* {
            PlanBuilder<D> builder(catalog_, arena_);
            PlanNode* plan = builder.build(ast);
            if (plan && distribute_fn_) {
                plan = distribute_fn_(plan);
            }
            return plan;
        });
        // Execute plan callback: create a fresh executor for the subquery
        // to avoid interfering with the outer operator tree.
        // Uses IndependentCursorDataSource wrappers to avoid resetting
        // the outer query's scan cursors when both scan the same table.
        subquery_exec_.set_execute_plan([this](PlanNode* plan) -> ResultSet {
            PlanExecutor<D> inner_exec(functions_, catalog_, subquery_plan_arena_);
            // Create independent cursor wrappers for each data source
            std::vector<std::unique_ptr<IndependentCursorDataSource>> wrappers;
            for (auto& kv : sources_) {
                auto* in_mem = dynamic_cast<InMemoryDataSource*>(kv.second);
                if (in_mem) {
                    auto wrapper = std::make_unique<IndependentCursorDataSource>(in_mem);
                    inner_exec.add_data_source(kv.first.c_str(), wrapper.get());
                    wrappers.push_back(std::move(wrapper));
                } else {
                    inner_exec.add_data_source(kv.first.c_str(), kv.second);
                }
            }
            if (remote_executor_)
                inner_exec.set_remote_executor(remote_executor_);
            return inner_exec.execute(plan);
        });
        // Correlated execution: pass outer resolver as fallback.
        // The inner executor's operators will try inner columns first,
        // then fall back to the outer resolver for unresolved names.
        // Note: we use the outer executor's arena for the inner plan build,
        // but create a separate arena for inner execution to avoid corruption.
        subquery_exec_.set_execute_plan_correlated(
            [this](PlanNode* plan,
                   const std::function<Value(sql_parser::StringRef)>& outer_resolve) -> ResultSet {
                PlanExecutor<D> inner_exec(functions_, catalog_, subquery_plan_arena_);
                // Create independent cursor wrappers for each data source
                std::vector<std::unique_ptr<IndependentCursorDataSource>> wrappers;
                for (auto& kv : sources_) {
                    auto* in_mem = dynamic_cast<InMemoryDataSource*>(kv.second);
                    if (in_mem) {
                        auto wrapper = std::make_unique<IndependentCursorDataSource>(in_mem);
                        inner_exec.add_data_source(kv.first.c_str(), wrapper.get());
                        wrappers.push_back(std::move(wrapper));
                    } else {
                        inner_exec.add_data_source(kv.first.c_str(), kv.second);
                    }
                }
                if (remote_executor_)
                    inner_exec.set_remote_executor(remote_executor_);
                inner_exec.set_outer_resolver(outer_resolve);
                return inner_exec.execute(plan);
            });
    }

    // Set an outer resolver for correlated subquery support.
    // When set, filter and project operators will fall back to this
    // resolver for column names not found in inner tables.
    void set_outer_resolver(const std::function<Value(sql_parser::StringRef)>& resolver) {
        outer_resolver_ = resolver;
    }

    // Look up mutable data source by table name (case-insensitive)
    MutableDataSource* find_mutable_source(const TableInfo* table) {
        if (!table) return nullptr;
        std::string name(table->table_name.ptr, table->table_name.len);
        for (auto& c : name) { if (c >= 'A' && c <= 'Z') c += 32; }
        auto it = mutable_sources_.find(name);
        if (it == mutable_sources_.end()) return nullptr;
        return it->second;
    }

    DmlResult execute_insert(PlanNode* plan) {
        DmlResult result;
        const auto& ip = plan->insert_plan;
        MutableDataSource* source = find_mutable_source(ip.table);
        if (!source) {
            result.error_message = "no mutable data source for table";
            return result;
        }

        const TableInfo* table = ip.table;
        if (!table) {
            result.error_message = "no table info";
            return result;
        }

        // Build column ordinal mapping
        // If columns are specified, map column names to ordinals
        // Otherwise, use natural order
        std::vector<uint16_t> col_ordinals;
        if (ip.columns && ip.column_count > 0) {
            for (uint16_t i = 0; i < ip.column_count; ++i) {
                const sql_parser::AstNode* col_node = ip.columns[i];
                if (col_node) {
                    sql_parser::StringRef col_name = col_node->value();
                    const ColumnInfo* ci = catalog_.get_column(table, col_name);
                    if (ci) {
                        col_ordinals.push_back(ci->ordinal);
                    } else {
                        col_ordinals.push_back(i); // fallback
                    }
                }
            }
        } else {
            for (uint16_t i = 0; i < table->column_count; ++i) {
                col_ordinals.push_back(i);
            }
        }

        // Resolver that returns null for all columns (used for constant expressions)
        auto null_resolve = [](sql_parser::StringRef) -> Value { return value_null(); };

        // Iterate value rows
        uint64_t inserted = 0;
        for (uint16_t ri = 0; ri < ip.row_count; ++ri) {
            const sql_parser::AstNode* row_ast = ip.value_rows[ri];
            if (!row_ast) continue;

            Row row = make_row(arena_, table->column_count);
            // Initialize all columns to NULL
            for (uint16_t c = 0; c < table->column_count; ++c) {
                row.set(c, value_null());
            }

            // Evaluate each expression in the values row
            uint16_t col_idx = 0;
            for (const sql_parser::AstNode* expr = row_ast->first_child;
                 expr && col_idx < col_ordinals.size();
                 expr = expr->next_sibling, ++col_idx) {
                Value v = evaluate_expression<D>(expr, null_resolve, functions_, arena_);
                row.set(col_ordinals[col_idx], v);
            }

            if (source->insert(row)) {
                ++inserted;
            }
        }

        result.affected_rows = inserted;
        result.success = true;
        return result;
    }

    DmlResult execute_update(PlanNode* plan) {
        DmlResult result;
        const auto& up = plan->update_plan;
        MutableDataSource* source = find_mutable_source(up.table);
        if (!source) {
            result.error_message = "no mutable data source for table";
            return result;
        }

        const TableInfo* table = up.table;
        if (!table) {
            result.error_message = "no table info";
            return result;
        }

        // Build predicate
        std::function<bool(const Row&)> predicate;
        if (up.where_expr) {
            predicate = [&](const Row& row) -> bool {
                auto resolver = make_resolver(catalog_, table, row.values);
                Value v = evaluate_expression<D>(up.where_expr, resolver, functions_, arena_);
                if (v.is_null()) return false;
                if (v.tag == Value::TAG_BOOL) return v.bool_val;
                if (v.tag == Value::TAG_INT64) return v.int_val != 0;
                return true;
            };
        } else {
            predicate = [](const Row&) { return true; };
        }

        // Build updater
        auto updater = [&](Row& row) {
            for (uint16_t i = 0; i < up.set_count; ++i) {
                const sql_parser::AstNode* col_node = up.set_columns[i];
                const sql_parser::AstNode* expr_node = up.set_exprs[i];
                if (!col_node || !expr_node) continue;

                sql_parser::StringRef col_name = col_node->value();
                const ColumnInfo* ci = catalog_.get_column(table, col_name);
                if (!ci) continue;

                // Evaluate expression with current row values (for SET age = age + 1)
                auto resolver = make_resolver(catalog_, table, row.values);
                Value v = evaluate_expression<D>(expr_node, resolver, functions_, arena_);
                row.set(ci->ordinal, v);
            }
        };

        uint64_t updated = source->update_where(predicate, updater);
        result.affected_rows = updated;
        result.success = true;
        return result;
    }

    DmlResult execute_delete(PlanNode* plan) {
        DmlResult result;
        const auto& dp = plan->delete_plan;
        MutableDataSource* source = find_mutable_source(dp.table);
        if (!source) {
            result.error_message = "no mutable data source for table";
            return result;
        }

        const TableInfo* table = dp.table;
        if (!table) {
            result.error_message = "no table info";
            return result;
        }

        // Build predicate
        std::function<bool(const Row&)> predicate;
        if (dp.where_expr) {
            predicate = [&](const Row& row) -> bool {
                auto resolver = make_resolver(catalog_, table, row.values);
                Value v = evaluate_expression<D>(dp.where_expr, resolver, functions_, arena_);
                if (v.is_null()) return false;
                if (v.tag == Value::TAG_BOOL) return v.bool_val;
                if (v.tag == Value::TAG_INT64) return v.int_val != 0;
                return true;
            };
        } else {
            predicate = [](const Row&) { return true; };
        }

        uint64_t deleted = source->delete_where(predicate);
        result.affected_rows = deleted;
        result.success = true;
        return result;
    }

    // Pre-process: for PROJECT -> AGGREGATE (or PROJECT -> FILTER -> AGGREGATE),
    // extract aggregate function expressions from the PROJECT select list
    // and push them into the AGGREGATE node.
    void preprocess_aggregates(PlanNode* node) {
        if (!node) return;
        // Recurse into derived scan's inner plan
        if (node->type == PlanNodeType::DERIVED_SCAN) {
            preprocess_aggregates(node->derived_scan.inner_plan);
            return;
        }
        preprocess_aggregates(node->left);
        preprocess_aggregates(node->right);

        if (node->type != PlanNodeType::PROJECT) return;

        // Find AGGREGATE child (possibly through SORT and/or FILTER for HAVING)
        PlanNode* agg_node = node->left;
        if (agg_node && agg_node->type == PlanNodeType::SORT)
            agg_node = agg_node->left;
        if (agg_node && agg_node->type == PlanNodeType::FILTER)
            agg_node = agg_node->left;
        if (!agg_node || agg_node->type != PlanNodeType::AGGREGATE) return;
        if (agg_node->aggregate.agg_count > 0) return; // already populated

        // Scan the PROJECT expressions for function calls that are aggregates
        std::vector<const sql_parser::AstNode*> agg_exprs;
        std::vector<const sql_parser::AstNode*> group_exprs;

        for (uint16_t i = 0; i < node->project.count; ++i) {
            const sql_parser::AstNode* expr = node->project.exprs[i];
            if (is_aggregate_expr(expr)) {
                agg_exprs.push_back(expr);
            } else {
                group_exprs.push_back(expr);
            }
        }

        if (agg_exprs.empty()) return;

        // Store aggregate expressions in the AGGREGATE node
        uint16_t ac = static_cast<uint16_t>(agg_exprs.size());
        auto** arr = static_cast<const sql_parser::AstNode**>(
            arena_.allocate(sizeof(sql_parser::AstNode*) * ac));
        for (uint16_t i = 0; i < ac; ++i) arr[i] = agg_exprs[i];
        agg_node->aggregate.agg_exprs = arr;
        agg_node->aggregate.agg_count = ac;

        // Replace the PROJECT with one that reads from the AGGREGATE output:
        // group_by columns first, then aggregate columns
        // Rewrite the PROJECT expressions to be positional column refs
        // Actually, we'll handle this differently: remove the PROJECT node
        // and let the AGGREGATE produce the final columns directly.
        // We remove the project by replacing node's type.

        // The simplest approach: the AGGREGATE now has group_by + agg_exprs,
        // it produces [group_val_0, ..., group_val_n, agg_val_0, ..., agg_val_m].
        // We keep the PROJECT but reorder its expressions to match:
        // group-by exprs first, then agg exprs.
        // Actually, let's just remove the PROJECT entirely since the AGGREGATE
        // output matches what we need.

        // Overwrite this PROJECT node to become a pass-through:
        // Change it into the node below it, preserving any intermediate
        // SORT and/or FILTER (HAVING) nodes.
        PlanNode* child = node->left;
        if (child && child->type == PlanNodeType::SORT) {
            // PROJECT -> SORT -> [FILTER ->] AGGREGATE
            // Replace PROJECT with SORT (preserving the sort)
            node->type = PlanNodeType::SORT;
            node->sort = child->sort;
            node->left = child->left;
            node->right = child->right;
        } else if (child && child->type == PlanNodeType::FILTER) {
            // PROJECT -> FILTER -> AGGREGATE: keep FILTER, remove PROJECT
            node->type = PlanNodeType::FILTER;
            node->filter.expr = child->filter.expr;
            node->left = child->left;
            node->right = child->right;
        } else {
            // PROJECT -> AGGREGATE: remove PROJECT, become AGGREGATE
            node->type = agg_node->type;
            node->aggregate = agg_node->aggregate;
            node->left = agg_node->left;
            node->right = agg_node->right;
        }
    }

    static bool is_aggregate_expr(const sql_parser::AstNode* expr) {
        if (!expr) return false;
        // Window functions are not aggregates for this purpose
        if (expr->type == sql_parser::NodeType::NODE_WINDOW_FUNCTION) return false;
        if (expr->type == sql_parser::NodeType::NODE_FUNCTION_CALL) {
            sql_parser::StringRef name = expr->value();
            if (name.equals_ci("COUNT", 5) || name.equals_ci("SUM", 3) ||
                name.equals_ci("AVG", 3) || name.equals_ci("MIN", 3) ||
                name.equals_ci("MAX", 3)) {
                return true;
            }
        }
        return false;
    }

    // Collect all tables referenced in a plan subtree
    void collect_tables(PlanNode* node, std::vector<const TableInfo*>& tables) {
        if (!node) return;
        if (node->type == PlanNodeType::DERIVED_SCAN) {
            if (node->derived_scan.synth_table) {
                tables.push_back(node->derived_scan.synth_table);
            }
            return;
        }
        if (node->type == PlanNodeType::SCAN) {
            if (node->scan.table) tables.push_back(node->scan.table);
            return;
        }
        if (node->type == PlanNodeType::REMOTE_SCAN) {
            if (node->remote_scan.table) tables.push_back(node->remote_scan.table);
            return;
        }
        if (node->type == PlanNodeType::MERGE_AGGREGATE) {
            for (uint16_t i = 0; i < node->merge_aggregate.child_count; ++i)
                collect_tables(node->merge_aggregate.children[i], tables);
            return;
        }
        if (node->type == PlanNodeType::MERGE_SORT) {
            for (uint16_t i = 0; i < node->merge_sort.child_count; ++i)
                collect_tables(node->merge_sort.children[i], tables);
            return;
        }
        if (node->type == PlanNodeType::WINDOW) {
            collect_tables(node->left, tables);
            return;
        }
        // For SET_OP (UNION ALL), only collect from left side to avoid
        // duplicating table entries when the same table appears on both
        // sides (e.g., sharded UNION ALL of RemoteScans for the same table).
        if (node->type == PlanNodeType::SET_OP) {
            collect_tables(node->left, tables);
            return;
        }
        collect_tables(node->left, tables);
        collect_tables(node->right, tables);
    }

    uint16_t count_columns(PlanNode* node) {
        if (!node) return 0;
        switch (node->type) {
            case PlanNodeType::SCAN: {
                if (node->scan.table) return node->scan.table->column_count;
                return 0;
            }
            case PlanNodeType::DERIVED_SCAN: {
                if (node->derived_scan.synth_table)
                    return node->derived_scan.synth_table->column_count;
                return count_columns(node->derived_scan.inner_plan);
            }
            case PlanNodeType::PROJECT:
                return node->project.count;
            case PlanNodeType::AGGREGATE:
                return node->aggregate.group_count + node->aggregate.agg_count;
            case PlanNodeType::JOIN:
                return count_columns(node->left) + count_columns(node->right);
            case PlanNodeType::FILTER:
            case PlanNodeType::SORT:
            case PlanNodeType::LIMIT:
            case PlanNodeType::DISTINCT:
                return count_columns(node->left);
            case PlanNodeType::SET_OP:
                return count_columns(node->left);
            case PlanNodeType::REMOTE_SCAN:
                if (node->remote_scan.table) return node->remote_scan.table->column_count;
                return 0;
            case PlanNodeType::MERGE_AGGREGATE:
                // Use stored output expression count if available
                if (node->merge_aggregate.output_expr_count > 0)
                    return node->merge_aggregate.output_expr_count;
                return node->merge_aggregate.group_key_count + node->merge_aggregate.merge_op_count;
            case PlanNodeType::MERGE_SORT:
                return count_columns(node->left);
            case PlanNodeType::WINDOW:
                return node->window.select_count;
            case PlanNodeType::INSERT_PLAN:
            case PlanNodeType::UPDATE_PLAN:
            case PlanNodeType::DELETE_PLAN:
                return 0; // DML nodes don't produce result columns
        }
        return 0;
    }

    Operator* build_operator(PlanNode* node) {
        if (!node) return nullptr;

        switch (node->type) {
            case PlanNodeType::SCAN:
                return build_scan(node);
            case PlanNodeType::DERIVED_SCAN:
                return build_derived_scan_op(node);
            case PlanNodeType::FILTER:
                return build_filter(node);
            case PlanNodeType::PROJECT:
                return build_project(node);
            case PlanNodeType::JOIN:
                return build_join(node);
            case PlanNodeType::AGGREGATE:
                return build_aggregate(node);
            case PlanNodeType::SORT:
                return build_sort(node);
            case PlanNodeType::LIMIT:
                return build_limit(node);
            case PlanNodeType::DISTINCT:
                return build_distinct(node);
            case PlanNodeType::SET_OP:
                return build_set_op(node);
            case PlanNodeType::REMOTE_SCAN:
                return build_remote_scan(node);
            case PlanNodeType::MERGE_AGGREGATE:
                return build_merge_aggregate(node);
            case PlanNodeType::MERGE_SORT:
                return build_merge_sort(node);
            case PlanNodeType::WINDOW:
                return build_window(node);
            case PlanNodeType::INSERT_PLAN:
            case PlanNodeType::UPDATE_PLAN:
            case PlanNodeType::DELETE_PLAN:
                return nullptr; // DML nodes are not executed as operators
        }
        return nullptr;
    }

    Operator* build_derived_scan_op(PlanNode* node) {
        // Build the inner plan's operator tree and wrap in DerivedScanOperator.
        // Pass the arena so deep-copied row data persists in the outer arena.
        Operator* inner = build_operator(node->derived_scan.inner_plan);
        if (!inner) return nullptr;
        auto op = std::make_unique<DerivedScanOperator>(inner, arena_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_scan(PlanNode* node) {
        const TableInfo* table = node->scan.table;
        if (!table) return nullptr;

        std::string name(table->table_name.ptr, table->table_name.len);
        // Lowercase for lookup
        for (auto& c : name) { if (c >= 'A' && c <= 'Z') c += 32; }

        auto it = sources_.find(name);
        if (it == sources_.end()) return nullptr;

        auto op = std::make_unique<ScanOperator>(it->second);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_filter(PlanNode* node) {
        Operator* child = build_operator(node->left);
        if (!child && node->left) return nullptr;

        std::vector<const TableInfo*> tables;
        collect_tables(node->left, tables);

        auto op = std::make_unique<FilterOperator<D>>(
            child, node->filter.expr, catalog_, tables, functions_, arena_,
            &subquery_exec_, outer_resolver_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_project(PlanNode* node) {
        Operator* child = nullptr;
        if (node->left) {
            child = build_operator(node->left);
            if (!child) return nullptr;
        }

        std::vector<const TableInfo*> tables;
        collect_tables(node->left, tables);

        auto op = std::make_unique<ProjectOperator<D>>(
            child, node->project.exprs, node->project.count,
            catalog_, tables, functions_, arena_, &subquery_exec_,
            outer_resolver_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_join(PlanNode* node) {
        Operator* left = build_operator(node->left);
        Operator* right = build_operator(node->right);
        if (!left || !right) return nullptr;

        std::vector<const TableInfo*> left_tables, right_tables;
        collect_tables(node->left, left_tables);
        collect_tables(node->right, right_tables);

        uint16_t left_cols = count_columns(node->left);
        uint16_t right_cols = count_columns(node->right);

        // Try hash join for INNER or LEFT equi-joins (#28).
        // An equi-join condition has the form: col_a = col_b
        if ((node->join.join_type == JOIN_INNER || node->join.join_type == JOIN_LEFT) &&
            node->join.condition) {
            uint16_t left_key = 0, right_key = 0;
            if (try_extract_equi_join_keys(node->join.condition,
                                            left_tables, right_tables,
                                            left_cols,
                                            left_key, right_key)) {
                auto op = std::make_unique<HashJoinOperator<D>>(
                    left, right, node->join.join_type,
                    left_key, right_key,
                    left_cols, right_cols, arena_);
                Operator* ptr = op.get();
                operators_.push_back(std::move(op));
                return ptr;
            }
        }

        // Fallback: nested-loop join (CROSS, non-equi, FULL, RIGHT, etc.)
        auto op = std::make_unique<NestedLoopJoinOperator<D>>(
            left, right, node->join.join_type, node->join.condition,
            left_cols, right_cols,
            catalog_, left_tables, right_tables, functions_, arena_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    // Try to extract column ordinals for an equi-join condition (col_a = col_b).
    // Returns true if the condition is a simple equality between a left-side
    // column and a right-side column.
    bool try_extract_equi_join_keys(
            const sql_parser::AstNode* condition,
            const std::vector<const TableInfo*>& left_tables,
            const std::vector<const TableInfo*>& right_tables,
            uint16_t /* left_cols */,
            uint16_t& left_key_out, uint16_t& right_key_out) {
        if (!condition) return false;
        if (condition->type != sql_parser::NodeType::NODE_BINARY_OP) return false;
        sql_parser::StringRef op = condition->value();
        if (!(op.len == 1 && op.ptr[0] == '=')) return false;

        const sql_parser::AstNode* lhs = condition->first_child;
        const sql_parser::AstNode* rhs = lhs ? lhs->next_sibling : nullptr;
        if (!lhs || !rhs) return false;

        // Both sides must be column references
        if (!is_column_ref(lhs) || !is_column_ref(rhs)) return false;

        sql_parser::StringRef lhs_name = extract_column_name(lhs);
        sql_parser::StringRef rhs_name = extract_column_name(rhs);
        if (!lhs_name.ptr || !rhs_name.ptr) return false;

        // Try lhs=left_col, rhs=right_col
        int left_ord = resolve_column_in_tables(lhs_name, left_tables);
        int right_ord = resolve_column_in_tables(rhs_name, right_tables);
        if (left_ord >= 0 && right_ord >= 0) {
            left_key_out = static_cast<uint16_t>(left_ord);
            right_key_out = static_cast<uint16_t>(right_ord);
            return true;
        }

        // Try swapped: lhs=right_col, rhs=left_col
        left_ord = resolve_column_in_tables(rhs_name, left_tables);
        right_ord = resolve_column_in_tables(lhs_name, right_tables);
        if (left_ord >= 0 && right_ord >= 0) {
            left_key_out = static_cast<uint16_t>(left_ord);
            right_key_out = static_cast<uint16_t>(right_ord);
            return true;
        }

        return false;
    }

    static bool is_column_ref(const sql_parser::AstNode* node) {
        return node &&
               (node->type == sql_parser::NodeType::NODE_COLUMN_REF ||
                node->type == sql_parser::NodeType::NODE_IDENTIFIER ||
                node->type == sql_parser::NodeType::NODE_QUALIFIED_NAME);
    }

    static sql_parser::StringRef extract_column_name(const sql_parser::AstNode* node) {
        if (!node) return {nullptr, 0};
        if (node->type == sql_parser::NodeType::NODE_COLUMN_REF ||
            node->type == sql_parser::NodeType::NODE_IDENTIFIER) {
            return node->value();
        }
        if (node->type == sql_parser::NodeType::NODE_QUALIFIED_NAME) {
            const sql_parser::AstNode* c = node->first_child;
            if (c && c->next_sibling) return c->next_sibling->value();
            if (c) return c->value();
        }
        return {nullptr, 0};
    }

    int resolve_column_in_tables(sql_parser::StringRef col_name,
                                  const std::vector<const TableInfo*>& tables) {
        uint16_t offset = 0;
        for (const auto* table : tables) {
            if (!table) continue;
            const ColumnInfo* col = catalog_.get_column(table, col_name);
            if (col) return static_cast<int>(offset + col->ordinal);
            offset += table->column_count;
        }
        return -1;
    }

    Operator* build_aggregate(PlanNode* node) {
        Operator* child = build_operator(node->left);
        if (!child && node->left) return nullptr;

        std::vector<const TableInfo*> tables;
        collect_tables(node->left, tables);

        // If agg_exprs not set by plan builder, try to extract from parent PROJECT
        // For now use what's in the plan node
        auto op = std::make_unique<AggregateOperator<D>>(
            child,
            node->aggregate.group_by, node->aggregate.group_count,
            node->aggregate.agg_exprs, node->aggregate.agg_count,
            catalog_, tables, functions_, arena_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_sort(PlanNode* node) {
        Operator* child = build_operator(node->left);
        if (!child) return nullptr;

        std::vector<const TableInfo*> tables;
        collect_tables(node->left, tables);

        auto op = std::make_unique<SortOperator<D>>(
            child, node->sort.keys, node->sort.directions, node->sort.count,
            catalog_, tables, functions_, arena_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_limit(PlanNode* node) {
        Operator* child = build_operator(node->left);
        if (!child) return nullptr;

        auto op = std::make_unique<LimitOperator>(
            child, node->limit.count, node->limit.offset);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_distinct(PlanNode* node) {
        Operator* child = build_operator(node->left);
        if (!child) return nullptr;

        auto op = std::make_unique<DistinctOperator>(child);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_set_op(PlanNode* node) {
        Operator* left = build_operator(node->left);
        Operator* right = build_operator(node->right);
        if (!left || !right) return nullptr;

        // Enable parallel open when both children are remote scans and executor is thread-safe
        bool parallel = parallel_open_enabled_ &&
                         (node->left && node->left->type == PlanNodeType::REMOTE_SCAN &&
                          node->right && node->right->type == PlanNodeType::REMOTE_SCAN);
        auto op = std::make_unique<SetOpOperator>(
            left, right, node->set_op.op, node->set_op.all, parallel,
            parallel ? pool_ : nullptr);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_remote_scan(PlanNode* node) {
        if (!remote_executor_) return nullptr;
        sql_parser::StringRef sql{node->remote_scan.remote_sql,
                                   node->remote_scan.remote_sql_len};
        auto op = std::make_unique<RemoteScanOperator>(
            remote_executor_, node->remote_scan.backend_name, sql);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_merge_aggregate(PlanNode* node) {
        std::vector<Operator*> children;
        for (uint16_t i = 0; i < node->merge_aggregate.child_count; ++i) {
            Operator* child = build_operator(node->merge_aggregate.children[i]);
            if (child) children.push_back(child);
        }
        if (children.empty()) return nullptr;

        // Enable parallel open when children are RemoteScans and executor is thread-safe
        bool parallel = parallel_open_enabled_ &&
                         (children.size() > 1) && has_remote_scan_children(node);
        auto op = std::make_unique<MergeAggregateOperator>(
            std::move(children),
            node->merge_aggregate.group_key_count,
            node->merge_aggregate.merge_ops,
            node->merge_aggregate.merge_op_count,
            arena_,
            parallel,
            parallel ? pool_ : nullptr);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    Operator* build_merge_sort(PlanNode* node) {
        std::vector<Operator*> children;
        for (uint16_t i = 0; i < node->merge_sort.child_count; ++i) {
            Operator* child = build_operator(node->merge_sort.children[i]);
            if (child) children.push_back(child);
        }
        if (children.empty()) return nullptr;

        // We need column indices for sort keys. The sort keys are AST nodes
        // (column references). We need to map them to column ordinals.
        // For distributed plans, sort keys reference columns by name in the
        // result schema. We use the table info from the first child to resolve.
        const TableInfo* table = nullptr;
        if (node->merge_sort.children[0]->type == PlanNodeType::REMOTE_SCAN) {
            table = node->merge_sort.children[0]->remote_scan.table;
        }

        std::vector<uint16_t> sort_col_indices;
        std::vector<uint8_t> sort_dirs;
        for (uint16_t i = 0; i < node->merge_sort.key_count; ++i) {
            const sql_parser::AstNode* key = node->merge_sort.keys[i];
            uint16_t col_idx = resolve_column_index(key, table);
            sort_col_indices.push_back(col_idx);
            sort_dirs.push_back(node->merge_sort.directions[i]);
        }

        // Enable parallel open when children are RemoteScans and executor is thread-safe
        bool parallel = parallel_open_enabled_ &&
                         (children.size() > 1) && has_remote_scan_children_merge_sort(node);
        auto op = std::make_unique<MergeSortOperator>(
            std::move(children),
            sort_col_indices.data(),
            sort_dirs.data(),
            node->merge_sort.key_count,
            parallel,
            parallel ? pool_ : nullptr);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    // Check whether all children of a MERGE_AGGREGATE node are REMOTE_SCAN.
    static bool has_remote_scan_children(const PlanNode* node) {
        if (!node || node->type != PlanNodeType::MERGE_AGGREGATE) return false;
        for (uint16_t i = 0; i < node->merge_aggregate.child_count; ++i) {
            if (node->merge_aggregate.children[i]->type != PlanNodeType::REMOTE_SCAN)
                return false;
        }
        return node->merge_aggregate.child_count > 0;
    }

    // Check whether all children of a MERGE_SORT node are REMOTE_SCAN.
    static bool has_remote_scan_children_merge_sort(const PlanNode* node) {
        if (!node || node->type != PlanNodeType::MERGE_SORT) return false;
        for (uint16_t i = 0; i < node->merge_sort.child_count; ++i) {
            if (node->merge_sort.children[i]->type != PlanNodeType::REMOTE_SCAN)
                return false;
        }
        return node->merge_sort.child_count > 0;
    }

    uint16_t resolve_column_index(const sql_parser::AstNode* key, const TableInfo* table) {
        if (!key || !table) return 0;
        sql_parser::StringRef col_name;
        if (key->type == sql_parser::NodeType::NODE_COLUMN_REF ||
            key->type == sql_parser::NodeType::NODE_IDENTIFIER) {
            col_name = key->value();
        } else if (key->type == sql_parser::NodeType::NODE_QUALIFIED_NAME) {
            // table.column -- get the column part
            const sql_parser::AstNode* c = key->first_child;
            if (c && c->next_sibling) col_name = c->next_sibling->value();
            else if (c) col_name = c->value();
        }
        if (col_name.ptr) {
            const ColumnInfo* col = catalog_.get_column(table, col_name);
            if (col) return col->ordinal;
        }
        return 0;
    }

    Operator* build_window(PlanNode* node) {
        Operator* child = build_operator(node->left);
        if (!child && node->left) return nullptr;

        std::vector<const TableInfo*> tables;
        collect_tables(node->left, tables);

        auto op = std::make_unique<WindowOperator<D>>(
            child,
            node->window.window_exprs, node->window.window_count,
            node->window.select_exprs, node->window.select_count,
            catalog_, tables, functions_, arena_);
        Operator* ptr = op.get();
        operators_.push_back(std::move(op));
        return ptr;
    }

    void build_column_names(PlanNode* plan, ResultSet& rs) {
        if (!plan) return;

        switch (plan->type) {
            case PlanNodeType::PROJECT: {
                for (uint16_t i = 0; i < plan->project.count; ++i) {
                    if (plan->project.aliases && plan->project.aliases[i]) {
                        sql_parser::StringRef av = plan->project.aliases[i]->value();
                        rs.column_names.emplace_back(av.ptr, av.len);
                    } else if (plan->project.exprs[i]) {
                        // Use expression text as column name
                        sql_parser::StringRef ev = plan->project.exprs[i]->value();
                        if (ev.ptr && ev.len > 0)
                            rs.column_names.emplace_back(ev.ptr, ev.len);
                        else
                            rs.column_names.push_back("?column?");
                    } else {
                        rs.column_names.push_back("?column?");
                    }
                }
                break;
            }
            case PlanNodeType::SCAN: {
                if (plan->scan.table) {
                    for (uint16_t i = 0; i < plan->scan.table->column_count; ++i) {
                        auto& cn = plan->scan.table->columns[i].name;
                        rs.column_names.emplace_back(cn.ptr, cn.len);
                    }
                }
                break;
            }
            case PlanNodeType::REMOTE_SCAN: {
                // Prefer the projection expressions the planner attached
                // (set by make_remote_scan_with_outputs for aggregate or
                // projected pushdown). Fall back to the table's catalog
                // columns only for SELECT * passthrough.
                if (plan->remote_scan.output_exprs &&
                    plan->remote_scan.output_expr_count > 0) {
                    for (uint16_t i = 0; i < plan->remote_scan.output_expr_count; ++i) {
                        const sql_parser::AstNode* expr = plan->remote_scan.output_exprs[i];
                        if (expr) {
                            sql_parser::Emitter<D> emitter(arena_);
                            emitter.emit(expr);
                            sql_parser::StringRef ev = emitter.result();
                            if (ev.ptr && ev.len > 0)
                                rs.column_names.emplace_back(ev.ptr, ev.len);
                            else
                                rs.column_names.push_back("?column?");
                        } else {
                            rs.column_names.push_back("?column?");
                        }
                    }
                } else if (plan->remote_scan.table) {
                    for (uint16_t i = 0; i < plan->remote_scan.table->column_count; ++i) {
                        auto& cn = plan->remote_scan.table->columns[i].name;
                        rs.column_names.emplace_back(cn.ptr, cn.len);
                    }
                }
                break;
            }
            case PlanNodeType::DERIVED_SCAN:
                if (plan->derived_scan.synth_table) {
                    for (uint16_t i = 0; i < plan->derived_scan.synth_table->column_count; ++i) {
                        auto& cn = plan->derived_scan.synth_table->columns[i].name;
                        rs.column_names.emplace_back(cn.ptr, cn.len);
                    }
                } else {
                    build_column_names(plan->derived_scan.inner_plan, rs);
                }
                break;
            case PlanNodeType::WINDOW: {
                for (uint16_t i = 0; i < plan->window.select_count; ++i) {
                    if (plan->window.select_aliases && plan->window.select_aliases[i]) {
                        sql_parser::StringRef av = plan->window.select_aliases[i]->value();
                        rs.column_names.emplace_back(av.ptr, av.len);
                    } else if (plan->window.select_exprs[i]) {
                        const sql_parser::AstNode* expr = plan->window.select_exprs[i];
                        if (expr->type == sql_parser::NodeType::NODE_WINDOW_FUNCTION) {
                            // Use the function name from the window function
                            const sql_parser::AstNode* func = expr->first_child;
                            if (func) {
                                sql_parser::StringRef ev = func->value();
                                if (ev.ptr && ev.len > 0)
                                    rs.column_names.emplace_back(ev.ptr, ev.len);
                                else
                                    rs.column_names.push_back("?column?");
                            } else {
                                rs.column_names.push_back("?column?");
                            }
                        } else {
                            sql_parser::StringRef ev = expr->value();
                            if (ev.ptr && ev.len > 0)
                                rs.column_names.emplace_back(ev.ptr, ev.len);
                            else
                                rs.column_names.push_back("?column?");
                        }
                    } else {
                        rs.column_names.push_back("?column?");
                    }
                }
                break;
            }
            case PlanNodeType::AGGREGATE: {
                // Group-by columns first, then aggregate columns
                for (uint16_t i = 0; i < plan->aggregate.group_count; ++i) {
                    const sql_parser::AstNode* expr = plan->aggregate.group_by[i];
                    if (expr) {
                        sql_parser::StringRef ev = expr->value();
                        if (ev.ptr && ev.len > 0)
                            rs.column_names.emplace_back(ev.ptr, ev.len);
                        else
                            rs.column_names.push_back("?column?");
                    } else {
                        rs.column_names.push_back("?column?");
                    }
                }
                for (uint16_t i = 0; i < plan->aggregate.agg_count; ++i) {
                    const sql_parser::AstNode* expr = plan->aggregate.agg_exprs[i];
                    if (expr) {
                        sql_parser::StringRef ev = expr->value();
                        if (ev.ptr && ev.len > 0)
                            rs.column_names.emplace_back(ev.ptr, ev.len);
                        else
                            rs.column_names.push_back("?column?");
                    } else {
                        rs.column_names.push_back("?column?");
                    }
                }
                break;
            }
            case PlanNodeType::MERGE_AGGREGATE: {
                // Use the stored output expressions for column naming
                if (plan->merge_aggregate.output_exprs &&
                    plan->merge_aggregate.output_expr_count > 0) {
                    for (uint16_t i = 0; i < plan->merge_aggregate.output_expr_count; ++i) {
                        const sql_parser::AstNode* expr = plan->merge_aggregate.output_exprs[i];
                        if (expr) {
                            // Use the emitter to produce a readable name
                            sql_parser::Emitter<D> emitter(arena_);
                            emitter.emit(expr);
                            sql_parser::StringRef name = emitter.result();
                            if (name.ptr && name.len > 0) {
                                rs.column_names.emplace_back(name.ptr, name.len);
                            } else {
                                rs.column_names.push_back("?column?");
                            }
                        } else {
                            rs.column_names.push_back("?column?");
                        }
                    }
                } else {
                    build_column_names(plan->left, rs);
                }
                break;
            }
            default:
                // For wrapping operators, recurse to child
                build_column_names(plan->left, rs);
                break;
        }
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_PLAN_EXECUTOR_H
