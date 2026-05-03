#ifndef SQL_ENGINE_OPERATORS_MERGE_AGGREGATE_OP_H
#define SQL_ENGINE_OPERATORS_MERGE_AGGREGATE_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/value.h"
#include "sql_engine/row.h"
#include "sql_engine/thread_pool.h"
#include "sql_parser/arena.h"
#include <vector>
#include <unordered_map>
#include <string>
#include <cstring>
#include <future>
#include <stdexcept>

namespace sql_engine {

// Merge operation types for distributed aggregation
// These define how partial aggregates from multiple shards are combined.
enum class MergeOp : uint8_t {
    SUM_OF_COUNTS   = 0,  // COUNT(*) or COUNT(col): sum the partial counts
    SUM_OF_SUMS     = 1,  // SUM(col): sum the partial sums
    MIN_OF_MINS     = 2,  // MIN(col): min of partial mins
    MAX_OF_MAXES    = 3,  // MAX(col): max of partial maxes
    AVG_SUM         = 4,  // AVG decomposed: this column holds the partial SUM
    AVG_COUNT       = 5,  // AVG decomposed: this column holds the partial COUNT
};

class MergeAggregateOperator : public Operator {
public:
    MergeAggregateOperator(std::vector<Operator*> children,
                           uint16_t group_key_count,
                           const uint8_t* merge_ops,
                           uint16_t merge_op_count,
                           sql_parser::Arena& arena,
                           bool parallel_open = false,
                           ThreadPool* pool = nullptr)
        : children_(std::move(children)),
          group_key_count_(group_key_count),
          merge_op_count_(merge_op_count),
          arena_(arena),
          parallel_open_(parallel_open),
          pool_(pool)
    {
        merge_ops_.assign(merge_ops, merge_ops + merge_op_count);
    }

    void open() override {
        groups_.clear();
        group_order_.clear();
        result_idx_ = 0;

        if (parallel_open_ && children_.size() > 1) {
            // Parallel execution: open all children concurrently and
            // materialize their rows. Uses thread pool when available
            // (~1-2us dispatch) vs std::async (~200us thread creation).
            std::vector<std::vector<Row>> child_rows(children_.size());
            {
                std::vector<std::future<void>> futures;
                futures.reserve(children_.size());
                for (size_t ci = 0; ci < children_.size(); ++ci) {
                    auto launcher = [this, ci, &child_rows]{
                        children_[ci]->open();
                        Row row{};
                        while (children_[ci]->next(row)) {
                            child_rows[ci].push_back(row);
                        }
                        children_[ci]->close();
                    };
                    if (pool_) {
                        futures.push_back(pool_->submit(std::move(launcher)));
                    } else {
                        futures.push_back(std::async(std::launch::async, std::move(launcher)));
                    }
                }
                for (auto& f : futures) f.get();
            }
            // Merge all materialized rows
            for (auto& rows : child_rows) {
                for (auto& row : rows) {
                    merge_into_groups(row);
                }
            }
            return;
        }

        // Sequential path: open and consume each child one at a time
        for (auto* child : children_) {
            child->open();
            Row row{};
            while (child->next(row)) {
                merge_into_groups(row);
            }
            child->close();
        }
    }

    bool next(Row& out) override {
        if (result_idx_ >= group_order_.size()) return false;

        const auto& key = group_order_[result_idx_++];
        const auto& state = groups_[key];

        // Compute output column count: group keys + final agg columns
        // We need to count actual output columns (AVG_SUM + AVG_COUNT -> 1 output)
        uint16_t output_agg_count = 0;
        for (uint16_t i = 0; i < merge_op_count_; ++i) {
            if (merge_ops_[i] != static_cast<uint8_t>(MergeOp::AVG_COUNT)) {
                output_agg_count++;
            }
        }

        uint16_t cols = group_key_count_ + output_agg_count;
        out = make_row(arena_, cols);

        for (uint16_t i = 0; i < group_key_count_; ++i) {
            out.set(i, state.group_values[i]);
        }

        uint16_t out_idx = group_key_count_;
        for (uint16_t i = 0; i < merge_op_count_; ++i) {
            MergeOp op = static_cast<MergeOp>(merge_ops_[i]);
            if (op == MergeOp::AVG_COUNT) continue; // consumed by AVG_SUM

            if (op == MergeOp::AVG_SUM) {
                // Find the corresponding AVG_COUNT (next column)
                double sum = state.agg_values[i].is_null() ? 0.0 : state.agg_values[i].to_double();
                int64_t count = 0;
                // Look for the AVG_COUNT that follows
                if (i + 1 < merge_op_count_ &&
                    merge_ops_[i + 1] == static_cast<uint8_t>(MergeOp::AVG_COUNT)) {
                    count = state.agg_values[i + 1].is_null() ? 0 : state.agg_values[i + 1].to_int64();
                }
                if (count > 0) {
                    out.set(out_idx++, value_double(sum / static_cast<double>(count)));
                } else {
                    out.set(out_idx++, value_null());
                }
            } else {
                out.set(out_idx++, state.agg_values[i]);
            }
        }
        return true;
    }

    void close() override {
        groups_.clear();
        group_order_.clear();
    }

private:
    std::vector<Operator*> children_;
    uint16_t group_key_count_;
    std::vector<uint8_t> merge_ops_;
    uint16_t merge_op_count_;
    sql_parser::Arena& arena_;
    bool parallel_open_;
    ThreadPool* pool_ = nullptr;

    struct GroupState {
        std::vector<Value> group_values;
        std::vector<Value> agg_values;
        std::unordered_map<uint16_t, int64_t> agg_counts;
        std::unordered_map<uint16_t, bool> agg_has_value;
    };

    std::unordered_map<std::string, GroupState> groups_;
    std::vector<std::string> group_order_;
    size_t result_idx_ = 0;

    void merge_into_groups(const Row& row) {
        // Validate that the row's schema matches what DistributedPlanner
        // promised: exactly [group_key_count_ group keys] +
        // [merge_op_count_ partial aggregate columns]. Previously, mismatched
        // schemas were silently truncated by `if (col_idx >= row.column_count)
        // continue;` in merge_row, producing silently-wrong aggregates. Throw
        // a clear error instead so a remote schema drift is caught at the
        // first row.
        check_row_schema(row);

        std::string key = compute_group_key(row);
        auto it = groups_.find(key);
        if (it == groups_.end()) {
            GroupState state;
            for (uint16_t i = 0; i < group_key_count_; ++i) {
                state.group_values.push_back(row.get(i));
            }
            state.agg_values.reserve(merge_op_count_);
            for (uint16_t i = 0; i < merge_op_count_; ++i) {
                state.agg_values.push_back(value_null());
                state.agg_counts[i] = 0;
                state.agg_has_value[i] = false;
            }
            groups_[key] = std::move(state);
            group_order_.push_back(key);
            it = groups_.find(key);
        }
        merge_row(it->second, row);
    }

    // Expected schema is exactly group_key_count_ + merge_op_count_ columns,
    // in that order. We compute it once into expected_col_count_ on the first
    // row to avoid recomputing per row. A mismatch on any row aborts the
    // merge with a clear error message instead of silently corrupting state.
    void check_row_schema(const Row& row) {
        const uint16_t expected =
            static_cast<uint16_t>(group_key_count_ + merge_op_count_);
        if (row.column_count != expected) {
            throw std::runtime_error(
                "distributed aggregate merge: shard returned " +
                std::to_string(row.column_count) +
                " columns, expected " + std::to_string(expected) +
                " (" + std::to_string(group_key_count_) +
                " group key(s) + " + std::to_string(merge_op_count_) +
                " partial aggregate(s)). Remote shard schema does not match "
                "what DistributedPlanner built; aborting to avoid silently "
                "corrupted aggregate results.");
        }
    }

    std::string compute_group_key(const Row& row) {
        std::string key;
        for (uint16_t i = 0; i < group_key_count_; ++i) {
            const Value& v = row.get(i);
            append_value_to_key(key, v);
            key += '\x01';
        }
        return key;
    }

    static void append_value_to_key(std::string& key, const Value& v) {
        if (v.is_null()) { key += "N"; return; }
        switch (v.tag) {
            case Value::TAG_BOOL: key += v.bool_val ? "T" : "F"; break;
            case Value::TAG_INT64: key += std::to_string(v.int_val); break;
            case Value::TAG_UINT64: key += std::to_string(v.uint_val); break;
            case Value::TAG_DOUBLE: key += std::to_string(v.double_val); break;
            case Value::TAG_STRING:
                key.append(v.str_val.ptr, v.str_val.len);
                break;
            default: key += "?"; break;
        }
    }

    void merge_row(GroupState& state, const Row& row) {
        // Schema is guaranteed by check_row_schema() above, so we can skip
        // bounds checks here. Defensive: still compute col_idx with the
        // expected layout.
        for (uint16_t i = 0; i < merge_op_count_; ++i) {
            uint16_t col_idx = group_key_count_ + i;
            Value v = row.get(col_idx);

            MergeOp op = static_cast<MergeOp>(merge_ops_[i]);
            switch (op) {
                case MergeOp::SUM_OF_COUNTS:
                case MergeOp::SUM_OF_SUMS:
                case MergeOp::AVG_SUM:
                case MergeOp::AVG_COUNT: {
                    if (v.is_null()) break;
                    if (!state.agg_has_value[i]) {
                        state.agg_values[i] = value_double(v.to_double());
                        state.agg_has_value[i] = true;
                    } else {
                        double cur = state.agg_values[i].to_double();
                        state.agg_values[i] = value_double(cur + v.to_double());
                    }
                    break;
                }
                case MergeOp::MIN_OF_MINS: {
                    if (v.is_null()) break;
                    if (!state.agg_has_value[i] || compare_values(v, state.agg_values[i]) < 0) {
                        state.agg_values[i] = v;
                        state.agg_has_value[i] = true;
                    }
                    break;
                }
                case MergeOp::MAX_OF_MAXES: {
                    if (v.is_null()) break;
                    if (!state.agg_has_value[i] || compare_values(v, state.agg_values[i]) > 0) {
                        state.agg_values[i] = v;
                        state.agg_has_value[i] = true;
                    }
                    break;
                }
            }
        }
    }

    static int compare_values(const Value& a, const Value& b) {
        if (a.is_null() && b.is_null()) return 0;
        if (a.is_null()) return -1;
        if (b.is_null()) return 1;
        if (a.is_numeric() && b.is_numeric()) {
            double da = a.to_double(), db = b.to_double();
            return da < db ? -1 : (da > db ? 1 : 0);
        }
        if (a.tag == Value::TAG_STRING && b.tag == Value::TAG_STRING) {
            uint32_t minlen = a.str_val.len < b.str_val.len ? a.str_val.len : b.str_val.len;
            int cmp = std::memcmp(a.str_val.ptr, b.str_val.ptr, minlen);
            if (cmp != 0) return cmp;
            return a.str_val.len < b.str_val.len ? -1 : (a.str_val.len > b.str_val.len ? 1 : 0);
        }
        return 0;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_MERGE_AGGREGATE_OP_H
