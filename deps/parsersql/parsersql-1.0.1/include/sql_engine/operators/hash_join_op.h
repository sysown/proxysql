#ifndef SQL_ENGINE_OPERATORS_HASH_JOIN_OP_H
#define SQL_ENGINE_OPERATORS_HASH_JOIN_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/catalog.h"
#include "sql_engine/plan_node.h"
#include "sql_engine/engine_limits.h"
#include "sql_parser/arena.h"
#include <functional>
#include <vector>
#include <unordered_map>
#include <stdexcept>

namespace sql_engine {

// HashJoinOperator — builds a hash table on the right (build) side keyed by
// the equi-join column, then probes it with each row from the left (probe)
// side.  O(n + m) for equi-joins, vs O(n * m) for nested-loop.
//
// Supports INNER and LEFT equi-joins.  Falls back to NestedLoopJoinOperator
// for non-equi or CROSS joins (selection is done in PlanExecutor::build_join).
template <sql_parser::Dialect D>
class HashJoinOperator : public Operator {
public:
    HashJoinOperator(Operator* left, Operator* right,
                     uint8_t join_type,
                     uint16_t left_join_col,   // ordinal of join key in left row
                     uint16_t right_join_col,  // ordinal of join key in right row
                     uint16_t left_cols, uint16_t right_cols,
                     sql_parser::Arena& arena)
        : left_(left), right_(right), join_type_(join_type),
          left_join_col_(left_join_col), right_join_col_(right_join_col),
          left_cols_(left_cols), right_cols_(right_cols),
          arena_(arena) {}

    void open() override {
        // Only INNER and LEFT equi-joins are actually supported below.
        // RIGHT/FULL/CROSS would silently fall through to INNER logic and
        // return wrong results. Reject explicitly. (CROSS also doesn't
        // belong here because it's not an equi-join; PlanExecutor's
        // build_join should never route it to the hash join operator.)
        if (join_type_ != JOIN_INNER && join_type_ != JOIN_LEFT) {
            throw std::runtime_error(
                "join type not supported by HashJoinOperator "
                "(only INNER and LEFT equi-joins are implemented; "
                "RIGHT, FULL and CROSS joins are not yet supported)");
        }

        // Build phase: consume right side into hash table keyed by join column
        hash_table_.clear();
        right_->open();
        Row r{};
        std::size_t total_build_rows = 0;
        while (right_->next(r)) {
            // Cap total build-side rows to prevent unbounded hash table.
            check_operator_row_limit(total_build_rows, kDefaultMaxOperatorRows, "HashJoinOperator");
            uint64_t h = hash_value(r.get(right_join_col_));
            hash_table_[h].push_back(copy_row(r));
            ++total_build_rows;
        }
        right_->close();

        // Probe side
        left_->open();
        probe_exhausted_ = false;
        has_probe_row_ = false;
        match_idx_ = 0;
        current_matches_ = nullptr;
        probe_matched_ = false;
    }

    bool next(Row& out) override {
        uint16_t total_cols = left_cols_ + right_cols_;

        while (true) {
            // Try to emit from current matches
            if (has_probe_row_ && current_matches_) {
                while (match_idx_ < current_matches_->size()) {
                    const Row& rr = (*current_matches_)[match_idx_];
                    match_idx_++;
                    // Verify actual equality (not just hash match)
                    if (values_equal(probe_row_.get(left_join_col_), rr.get(right_join_col_))) {
                        probe_matched_ = true;
                        out = combine_rows(probe_row_, rr, total_cols);
                        return true;
                    }
                }
            }

            // Done with current probe row's matches
            if (has_probe_row_ && join_type_ == JOIN_LEFT && !probe_matched_) {
                // LEFT JOIN: emit probe row with NULLs for right side
                out = make_row(arena_, total_cols);
                for (uint16_t i = 0; i < left_cols_ && i < probe_row_.column_count; ++i)
                    out.set(i, probe_row_.get(i));
                for (uint16_t i = 0; i < right_cols_; ++i)
                    out.set(left_cols_ + i, value_null());
                has_probe_row_ = false;
                return true;
            }

            // Advance to next probe row
            if (probe_exhausted_) return false;
            if (!left_->next(probe_row_)) {
                probe_exhausted_ = true;
                return false;
            }

            has_probe_row_ = true;
            probe_matched_ = false;
            match_idx_ = 0;

            uint64_t h = hash_value(probe_row_.get(left_join_col_));
            auto it = hash_table_.find(h);
            current_matches_ = (it != hash_table_.end()) ? &it->second : nullptr;
        }
    }

    void close() override {
        left_->close();
        hash_table_.clear();
    }

private:
    Operator* left_;
    Operator* right_;
    uint8_t join_type_;
    uint16_t left_join_col_;
    uint16_t right_join_col_;
    uint16_t left_cols_;
    uint16_t right_cols_;
    sql_parser::Arena& arena_;

    std::unordered_map<uint64_t, std::vector<Row>> hash_table_;
    Row probe_row_{};
    bool has_probe_row_ = false;
    bool probe_exhausted_ = false;
    bool probe_matched_ = false;
    size_t match_idx_ = 0;
    const std::vector<Row>* current_matches_ = nullptr;

    Row copy_row(const Row& src) {
        Row dst = make_row(arena_, src.column_count);
        for (uint16_t i = 0; i < src.column_count; ++i)
            dst.set(i, src.get(i));
        return dst;
    }

    Row combine_rows(const Row& left, const Row& right, uint16_t total_cols) {
        Row out = make_row(arena_, total_cols);
        for (uint16_t i = 0; i < left_cols_ && i < left.column_count; ++i)
            out.set(i, left.get(i));
        for (uint16_t i = 0; i < right_cols_ && i < right.column_count; ++i)
            out.set(left_cols_ + i, right.get(i));
        return out;
    }

    static uint64_t hash_value(const Value& v) {
        if (v.is_null()) return 0;
        switch (v.tag) {
            case Value::TAG_BOOL:   return std::hash<bool>{}(v.bool_val);
            case Value::TAG_INT64:  return std::hash<int64_t>{}(v.int_val);
            case Value::TAG_UINT64: return std::hash<uint64_t>{}(v.uint_val);
            case Value::TAG_DOUBLE: return std::hash<double>{}(v.double_val);
            case Value::TAG_STRING: {
                // FNV-1a hash
                uint64_t h = 14695981039346656037ULL;
                for (uint32_t i = 0; i < v.str_val.len; ++i) {
                    h ^= static_cast<uint64_t>(static_cast<unsigned char>(v.str_val.ptr[i]));
                    h *= 1099511628211ULL;
                }
                return h;
            }
            default: return 0;
        }
    }

    static bool values_equal(const Value& a, const Value& b) {
        if (a.is_null() || b.is_null()) return false;
        if (a.tag == b.tag) {
            switch (a.tag) {
                case Value::TAG_BOOL:   return a.bool_val == b.bool_val;
                case Value::TAG_INT64:  return a.int_val == b.int_val;
                case Value::TAG_UINT64: return a.uint_val == b.uint_val;
                case Value::TAG_DOUBLE: return a.double_val == b.double_val;
                case Value::TAG_STRING:
                    return a.str_val.len == b.str_val.len &&
                           (a.str_val.len == 0 ||
                            std::memcmp(a.str_val.ptr, b.str_val.ptr, a.str_val.len) == 0);
                default: return false;
            }
        }
        // Cross-type numeric comparison
        if (a.is_numeric() && b.is_numeric()) {
            return a.to_double() == b.to_double();
        }
        return false;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_HASH_JOIN_OP_H
