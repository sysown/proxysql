#ifndef SQL_ENGINE_SESSION_H
#define SQL_ENGINE_SESSION_H

#include "sql_engine/transaction_manager.h"
#include "sql_engine/plan_executor.h"
#include "sql_engine/plan_builder.h"
#include "sql_engine/dml_plan_builder.h"
#include "sql_engine/optimizer.h"
#include "sql_engine/distributed_planner.h"
#include "sql_engine/shard_map.h"
#include "sql_engine/catalog.h"
#include "sql_engine/function_registry.h"
#include "sql_engine/result_set.h"
#include "sql_engine/dml_result.h"
#include "sql_engine/mutable_data_source.h"
#include "sql_parser/parser.h"
#include "sql_parser/common.h"

#include <cstring>
#include <string>
#include <functional>
#include <unordered_map>
#include <list>
#include <memory>

namespace sql_engine {

// Session<D> is the high-level API that ties together parsing, planning,
// optimization, execution, and transaction management.
//
// Usage:
//   Session<Dialect::MySQL> session(catalog, txn_mgr);
//   session.add_data_source("users", &users_source);
//   auto rs = session.execute_query("SELECT * FROM users");
//   auto dr = session.execute_statement("INSERT INTO users VALUES (1, 'a')");
//   session.begin();
//   session.commit();
template <sql_parser::Dialect D>
class Session {
public:
    Session(const Catalog& catalog, TransactionManager& txn_mgr)
        : catalog_(catalog), txn_mgr_(txn_mgr),
          functions_(), optimizer_(catalog, functions_) {
        functions_.register_builtins();
    }

    // Register data sources
    void add_data_source(const char* table_name, DataSource* source) {
        sources_[table_name] = source;
    }

    void add_mutable_data_source(const char* table_name, MutableDataSource* source) {
        mutable_sources_[table_name] = source;
        sources_[table_name] = source;
    }

    void set_remote_executor(RemoteExecutor* exec) {
        remote_executor_ = exec;
    }

    // Enable parallel opening of RemoteScan children. Only safe when the
    // RemoteExecutor is thread-safe (e.g. ThreadSafeMultiRemoteExecutor).
    void set_parallel_open(bool enabled) {
        parallel_open_enabled_ = enabled;
    }

    void set_shard_map(const ShardMap* sm) {
        shard_map_ = sm;
    }

    // Set a shared thread pool for parallel shard I/O dispatch.
    // The pool must outlive this session. Use with set_parallel_open(true).
    void set_thread_pool(ThreadPool* pool) {
        pool_ = pool;
    }

    // Configure the maximum number of cached plans. When the cache is full,
    // the least-recently-used entry is evicted on insert. Default is 1024.
    // Setting to 0 disables caching entirely.
    void set_plan_cache_max_size(size_t n) { plan_cache_max_size_ = n; }
    size_t plan_cache_size() const { return plan_cache_.size(); }

    // Execute a SELECT query. Returns a ResultSet.
    // Uses plan caching: repeated identical SQL strings skip parse/plan/optimize/distribute.
    ResultSet execute_query(const char* sql, size_t len) {
        // Check plan cache first
        std::string sql_key(sql, len);
        auto cache_it = plan_cache_.find(sql_key);
        if (cache_it != plan_cache_.end()) {
            // Cache hit: move this entry to the front of the LRU list.
            plan_cache_order_.splice(plan_cache_order_.begin(),
                                     plan_cache_order_,
                                     cache_it->second);
            exec_arena_.reset();
            auto& entry = *cache_it->second;
            PlanExecutor<D> executor(functions_, catalog_, exec_arena_);
            wire_executor(executor);
            return executor.execute(entry.plan);
        }

        // Cache miss: full parse -> plan -> optimize -> distribute pipeline
        auto cached_parser = std::make_unique<sql_parser::Parser<D>>();
        auto pr = cached_parser->parse(sql, len);
        if (pr.status != sql_parser::ParseResult::OK || !pr.ast) {
            return {};
        }

        // CTE queries route through PlanExecutor::execute_with_cte so the
        // WITH clause's CTE definitions are materialized into in-memory
        // data sources before the main SELECT runs. We deliberately do
        // NOT cache CTE plans: build_cte() produces only the main SELECT
        // plan with no CTE materialization, so a cache hit would silently
        // return wrong results. Per issue 07's "intentionally limited"
        // scope, CTEs re-parse + re-materialize on every call. Recursive
        // CTEs are still out of scope.
        if (pr.ast->type == sql_parser::NodeType::NODE_CTE) {
            PlanExecutor<D> executor(functions_, catalog_, cached_parser->arena());
            wire_executor(executor);
            return executor.execute_with_cte(pr.ast);
        }

        PlanBuilder<D> builder(catalog_, cached_parser->arena());
        PlanNode* plan = builder.build(pr.ast);
        if (!plan) return {};

        plan = optimizer_.optimize(plan, cached_parser->arena());

        // Distribute across shards if shard map is configured
        if (shard_map_ && remote_executor_) {
            DistributedPlanner<D> dplanner(*shard_map_, catalog_, cached_parser->arena(), remote_executor_, &functions_);
            plan = dplanner.distribute(plan);
        }

        // Execute first using the parser's arena. preprocess_aggregates (called
        // inside execute()) may allocate into the arena to modify the plan in-place.
        // Those allocations must persist in the parser arena (not exec_arena_) so
        // the cached plan remains valid across calls.
        PlanExecutor<D> executor(functions_, catalog_, cached_parser->arena());
        wire_executor(executor);
        ResultSet rs = executor.execute(plan);

        // Cache the plan, enforcing the LRU bound. The parser arena is kept
        // alive via unique_ptr stored in the CachedPlan so all plan/AST
        // string pointers remain valid for subsequent cache hits.
        insert_into_plan_cache(std::move(sql_key), std::move(cached_parser), plan);

        return rs;
    }

    ResultSet execute_query(const char* sql) {
        return execute_query(sql, std::strlen(sql));
    }

    // Execute a DML statement (INSERT/UPDATE/DELETE). Returns DmlResult.
    DmlResult execute_statement(const char* sql, size_t len) {
        parser_.reset();
        auto pr = parser_.parse(sql, len);

        // Check for transaction control statements first (parser may not
        // produce an AST for these — they are classified by stmt_type).
        switch (pr.stmt_type) {
            case sql_parser::StmtType::BEGIN:
            case sql_parser::StmtType::START_TRANSACTION: {
                DmlResult dr;
                dr.success = txn_mgr_.begin();
                if (!dr.success) dr.error_message = "BEGIN failed";
                return dr;
            }
            case sql_parser::StmtType::COMMIT: {
                DmlResult dr;
                dr.success = txn_mgr_.commit();
                if (!dr.success) dr.error_message = "COMMIT failed";
                return dr;
            }
            case sql_parser::StmtType::ROLLBACK: {
                DmlResult dr;
                dr.success = txn_mgr_.rollback();
                if (!dr.success) dr.error_message = "ROLLBACK failed";
                return dr;
            }
            case sql_parser::StmtType::SAVEPOINT: {
                DmlResult dr;
                // The savepoint name is in the AST value or table_name
                std::string name;
                if (pr.table_name.ptr && pr.table_name.len > 0)
                    name.assign(pr.table_name.ptr, pr.table_name.len);
                else if (pr.ast && pr.ast->value_ptr && pr.ast->value_len > 0)
                    name.assign(pr.ast->value_ptr, pr.ast->value_len);
                else
                    name = "sp";
                dr.success = txn_mgr_.savepoint(name.c_str());
                if (!dr.success) dr.error_message = "SAVEPOINT failed";
                return dr;
            }
            default:
                break;
        }

        // For non-transaction statements, need a valid parse + AST
        if (pr.status != sql_parser::ParseResult::OK || !pr.ast) {
            DmlResult dr;
            dr.error_message = "parse error";
            return dr;
        }

        // Regular DML
        DmlPlanBuilder<D> dml_builder(catalog_, parser_.arena());
        PlanNode* plan = dml_builder.build(pr.ast);
        if (!plan) {
            DmlResult dr;
            dr.error_message = "plan build error";
            return dr;
        }

        // Auto-commit: wrap in implicit transaction
        bool implicit_txn = txn_mgr_.is_auto_commit() && !txn_mgr_.in_transaction();
        if (implicit_txn) txn_mgr_.begin();

        DmlResult result;

        // If sharding is configured, distribute DML to remote backends.
        if (shard_map_ && remote_executor_) {
            DistributedPlanner<D> dp(*shard_map_, catalog_, parser_.arena(),
                                      remote_executor_, &functions_);
            PlanNode* dist_plan = dp.distribute_dml(plan);

            if (dist_plan && dist_plan->type == PlanNodeType::REMOTE_SCAN) {
                // Single-shard DML
                sql_parser::StringRef sql_ref{dist_plan->remote_scan.remote_sql,
                                              dist_plan->remote_scan.remote_sql_len};
                if (txn_mgr_.in_transaction() && txn_mgr_.is_distributed()) {
                    result = txn_mgr_.route_dml(dist_plan->remote_scan.backend_name, sql_ref);
                } else {
                    result = remote_executor_->execute_dml(
                        dist_plan->remote_scan.backend_name, sql_ref);
                }
            } else if (dist_plan && dist_plan->type == PlanNodeType::SET_OP) {
                // Scatter DML to multiple shards
                result.success = true;
                result.affected_rows = 0;
                for_each_remote_scan(dist_plan, [&](const PlanNode* rs) {
                    sql_parser::StringRef s{rs->remote_scan.remote_sql,
                                            rs->remote_scan.remote_sql_len};
                    DmlResult shard_result;
                    if (txn_mgr_.in_transaction() && txn_mgr_.is_distributed()) {
                        shard_result = txn_mgr_.route_dml(rs->remote_scan.backend_name, s);
                    } else {
                        shard_result = remote_executor_->execute_dml(
                            rs->remote_scan.backend_name, s);
                    }
                    if (!shard_result.success) {
                        result.success = false;
                        result.error_message = shard_result.error_message;
                    }
                    result.affected_rows += shard_result.affected_rows;
                });
            } else {
                // Not distributed (table not in shard map) -- local execution
                PlanExecutor<D> executor(functions_, catalog_, parser_.arena());
                wire_executor(executor);
                result = executor.execute_dml(plan);
            }
        } else {
            // No sharding: local execution
            PlanExecutor<D> executor(functions_, catalog_, parser_.arena());
            wire_executor(executor);
            result = executor.execute_dml(plan);
        }

        if (implicit_txn) {
            if (result.success)
                txn_mgr_.commit();
            else
                txn_mgr_.rollback();
        }

        return result;
    }

    DmlResult execute_statement(const char* sql) {
        return execute_statement(sql, std::strlen(sql));
    }

    // Transaction control
    bool begin() { return txn_mgr_.begin(); }
    bool commit() { return txn_mgr_.commit(); }
    bool rollback() { return txn_mgr_.rollback(); }
    bool savepoint(const char* name) { return txn_mgr_.savepoint(name); }
    bool rollback_to(const char* name) { return txn_mgr_.rollback_to(name); }

    void set_auto_commit(bool ac) { txn_mgr_.set_auto_commit(ac); }
    bool is_auto_commit() const { return txn_mgr_.is_auto_commit(); }
    bool in_transaction() const { return txn_mgr_.in_transaction(); }

    // Access internals (for testing)
    TransactionManager& txn_manager() { return txn_mgr_; }
    const Catalog& catalog() const { return catalog_; }

private:
    const Catalog& catalog_;
    TransactionManager& txn_mgr_;
    sql_parser::Parser<D> parser_;
    FunctionRegistry<D> functions_;
    Optimizer<D> optimizer_;
    RemoteExecutor* remote_executor_ = nullptr;
    const ShardMap* shard_map_ = nullptr;
    bool parallel_open_enabled_ = false;
    std::unordered_map<std::string, DataSource*> sources_;
    std::unordered_map<std::string, MutableDataSource*> mutable_sources_;

    // Per-query execution arena. Reset before each query execution so
    // per-query allocations (rows, operator internals) don't accumulate.
    sql_parser::Arena exec_arena_{65536, 1048576};

    // Thread pool for lightweight parallel shard I/O dispatch.
    // Externally owned; set via set_thread_pool(). Shared across sessions.
    ThreadPool* pool_ = nullptr;

    // Plan cache: bounded LRU keyed by SQL string. Each entry owns the
    // parser whose arena keeps the plan tree and all AST/plan string
    // pointers alive for as long as the entry stays in the cache.
    //
    // Implementation: a list keeps insertion/use order (front = most
    // recently used) and a hash map maps each SQL string to its iterator
    // in the list, giving O(1) lookup, O(1) move-to-front on hit, and
    // O(1) eviction of the LRU entry on insert.
    struct CachedPlan {
        std::string key;
        std::unique_ptr<sql_parser::Parser<D>> parser;
        PlanNode* plan;
    };
    using CacheList = std::list<CachedPlan>;
    using CacheIter = typename CacheList::iterator;
    CacheList plan_cache_order_;
    std::unordered_map<std::string, CacheIter> plan_cache_;
    size_t plan_cache_max_size_ = 1024;

    void insert_into_plan_cache(std::string key,
                                std::unique_ptr<sql_parser::Parser<D>> parser,
                                PlanNode* plan) {
        if (plan_cache_max_size_ == 0) return;  // caching disabled
        // Evict LRU entries until we're within budget. We evict before insert
        // so the new entry counts against the cap and we never exceed it.
        while (plan_cache_.size() >= plan_cache_max_size_ && !plan_cache_order_.empty()) {
            const std::string& victim_key = plan_cache_order_.back().key;
            plan_cache_.erase(victim_key);
            plan_cache_order_.pop_back();
        }
        CachedPlan entry;
        entry.key = std::move(key);
        entry.parser = std::move(parser);
        entry.plan = plan;
        plan_cache_order_.push_front(std::move(entry));
        // The map stores the iterator and a copy of the key (so the lookup
        // string and the entry's owned key both remain valid through moves).
        plan_cache_[plan_cache_order_.front().key] = plan_cache_order_.begin();
    }

    static void for_each_remote_scan(const PlanNode* node,
                                      const std::function<void(const PlanNode*)>& fn) {
        if (!node) return;
        if (node->type == PlanNodeType::REMOTE_SCAN) {
            fn(node);
            return;
        }
        if (node->type == PlanNodeType::SET_OP) {
            for_each_remote_scan(node->left, fn);
            for_each_remote_scan(node->right, fn);
        }
    }

    void wire_executor(PlanExecutor<D>& executor) {
        for (auto& kv : sources_)
            executor.add_data_source(kv.first.c_str(), kv.second);
        for (auto& kv : mutable_sources_)
            executor.add_mutable_data_source(kv.first.c_str(), kv.second);
        if (remote_executor_)
            executor.set_remote_executor(remote_executor_);
        if (parallel_open_enabled_) {
            executor.set_parallel_open(true);
            if (pool_)
                executor.set_thread_pool(pool_);
        }
        // If sharding is configured, provide a distribute callback so that
        // subqueries also go through the distributed planner.
        if (shard_map_ && remote_executor_) {
            executor.set_distribute_fn(
                [this](PlanNode* plan) -> PlanNode* {
                    DistributedPlanner<D> dp(*shard_map_, catalog_, parser_.arena(),
                                             remote_executor_, &functions_);
                    return dp.distribute(plan);
                });
        }
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_SESSION_H
