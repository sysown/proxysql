#ifndef SQL_ENGINE_OPERATORS_JOIN_OP_H
#define SQL_ENGINE_OPERATORS_JOIN_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/catalog.h"
#include "sql_engine/plan_node.h"
#include "sql_engine/engine_limits.h"
#include "sql_parser/arena.h"
#include <stdexcept>
#include <functional>
#include <vector>

namespace sql_engine {

template <sql_parser::Dialect D>
class NestedLoopJoinOperator : public Operator {
public:
    NestedLoopJoinOperator(Operator* left, Operator* right,
                           uint8_t join_type,
                           const sql_parser::AstNode* condition,
                           uint16_t left_cols, uint16_t right_cols,
                           const Catalog& catalog,
                           const std::vector<const TableInfo*>& left_tables,
                           const std::vector<const TableInfo*>& right_tables,
                           FunctionRegistry<D>& functions,
                           sql_parser::Arena& arena)
        : left_(left), right_(right), join_type_(join_type),
          condition_(condition), left_cols_(left_cols), right_cols_(right_cols),
          catalog_(catalog), left_tables_(left_tables), right_tables_(right_tables),
          functions_(functions), arena_(arena) {}

    void open() override {
        if (join_type_ != JOIN_INNER &&
            join_type_ != JOIN_LEFT &&
            join_type_ != JOIN_RIGHT &&
            join_type_ != JOIN_FULL &&
            join_type_ != JOIN_CROSS) {
            throw std::runtime_error(
                "join type not supported by NestedLoopJoinOperator "
                "(supported: INNER, LEFT, RIGHT, FULL, CROSS)");
        }

        // Materialize right side
        right_->open();
        right_rows_.clear();
        right_matched_.clear();
        Row r{};
        while (right_->next(r)) {
            // Cap right side to prevent O(n*m) explosion + OOM.
            check_operator_row_limit(right_rows_.size(), kDefaultMaxOperatorRows, "NestedLoopJoinOperator");
            right_rows_.push_back(r);
            right_matched_.push_back(false);
        }
        right_->close();

        left_->open();
        has_left_row_ = false;
        right_idx_ = 0;
        left_matched_ = false;
        left_exhausted_ = false;
        emitting_unmatched_right_ = false;
        unmatched_right_idx_ = 0;
    }

    bool next(Row& out) override {
        uint16_t total_cols = left_cols_ + right_cols_;

        while (true) {
            if (emitting_unmatched_right_) {
                while (unmatched_right_idx_ < right_rows_.size()) {
                    size_t idx = unmatched_right_idx_++;
                    if (right_matched_[idx]) continue;

                    out = make_row(arena_, total_cols);
                    for (uint16_t i = 0; i < left_cols_; ++i)
                        out.set(i, value_null());
                    for (uint16_t i = 0; i < right_cols_ && i < right_rows_[idx].column_count; ++i)
                        out.set(left_cols_ + i, right_rows_[idx].get(i));
                    return true;
                }
                return false;
            }

            if (!has_left_row_) {
                if (left_exhausted_) {
                    if (join_type_ == JOIN_RIGHT || join_type_ == JOIN_FULL) {
                        emitting_unmatched_right_ = true;
                        unmatched_right_idx_ = 0;
                        continue;
                    }
                    return false;
                }
                if (!left_->next(left_row_)) {
                    left_exhausted_ = true;
                    continue;
                }
                has_left_row_ = true;
                right_idx_ = 0;
                left_matched_ = false;
            }

            // CROSS JOIN or condition-based join
            if (join_type_ == JOIN_CROSS) {
                if (right_idx_ < right_rows_.size()) {
                    out = combine_rows(left_row_, right_rows_[right_idx_], total_cols);
                    right_idx_++;
                    return true;
                }
                has_left_row_ = false;
                continue;
            }

            // INNER / LEFT / RIGHT / FULL join
            while (right_idx_ < right_rows_.size()) {
                size_t match_idx = right_idx_++;
                const Row& rr = right_rows_[match_idx];

                Row combined = combine_rows(left_row_, rr, total_cols);
                if (!condition_ || eval_condition(combined)) {
                    left_matched_ = true;
                    right_matched_[match_idx] = true;
                    out = combined;
                    return true;
                }
            }

            // Done scanning right side for this left row
            if ((join_type_ == JOIN_LEFT || join_type_ == JOIN_FULL) && !left_matched_) {
                // Emit left row + NULL right side.
                out = make_row(arena_, total_cols);
                for (uint16_t i = 0; i < left_cols_; ++i)
                    out.set(i, left_row_.get(i));
                for (uint16_t i = 0; i < right_cols_; ++i)
                    out.set(left_cols_ + i, value_null());
                has_left_row_ = false;
                return true;
            }

            has_left_row_ = false;
        }
    }

    void close() override {
        left_->close();
        right_rows_.clear();
        right_matched_.clear();
    }

private:
    Operator* left_;
    Operator* right_;
    uint8_t join_type_;
    const sql_parser::AstNode* condition_;
    uint16_t left_cols_;
    uint16_t right_cols_;
    const Catalog& catalog_;
    std::vector<const TableInfo*> left_tables_;
    std::vector<const TableInfo*> right_tables_;
    FunctionRegistry<D>& functions_;
    sql_parser::Arena& arena_;

    std::vector<Row> right_rows_;
    std::vector<bool> right_matched_;
    Row left_row_{};
    bool has_left_row_ = false;
    size_t right_idx_ = 0;
    bool left_matched_ = false;
    bool left_exhausted_ = false;
    bool emitting_unmatched_right_ = false;
    size_t unmatched_right_idx_ = 0;

    Row combine_rows(const Row& left, const Row& right, uint16_t total_cols) {
        Row out = make_row(arena_, total_cols);
        for (uint16_t i = 0; i < left_cols_ && i < left.column_count; ++i)
            out.set(i, left.get(i));
        for (uint16_t i = 0; i < right_cols_ && i < right.column_count; ++i)
            out.set(left_cols_ + i, right.get(i));
        return out;
    }

    bool eval_condition(const Row& combined) {
        // Build a resolver over all tables (left then right)
        std::vector<const TableInfo*> all_tables;
        all_tables.insert(all_tables.end(), left_tables_.begin(), left_tables_.end());
        all_tables.insert(all_tables.end(), right_tables_.begin(), right_tables_.end());

        auto resolver = [this, &combined, &all_tables](sql_parser::StringRef col_name) -> Value {
            sql_parser::StringRef qualifier{nullptr, 0};
            sql_parser::StringRef base_name = col_name;
            bool qualified = split_qualified_name(col_name, qualifier, base_name);
            uint16_t offset = 0;
            for (const auto* table : all_tables) {
                if (!table) continue;
                if (qualified && !matches_table_qualifier(table, qualifier)) {
                    offset += table->column_count;
                    continue;
                }
                const ColumnInfo* col = catalog_.get_column(table, base_name);
                if (col) {
                    uint16_t idx = offset + col->ordinal;
                    if (idx < combined.column_count) return combined.get(idx);
                }
                offset += table->column_count;
            }
            return value_null();
        };

        Value result = evaluate_expression<D>(condition_, resolver, functions_, arena_);
        if (result.is_null()) return false;
        if (result.tag == Value::TAG_BOOL) return result.bool_val;
        if (result.tag == Value::TAG_INT64) return result.int_val != 0;
        return true;
    }

    static bool split_qualified_name(sql_parser::StringRef ref,
                                     sql_parser::StringRef& qualifier_out,
                                     sql_parser::StringRef& base_out) {
        if (!ref.ptr || ref.len == 0) return false;
        for (uint32_t i = 0; i < ref.len; ++i) {
            if (ref.ptr[i] == '.') {
                qualifier_out = sql_parser::StringRef{ref.ptr, i};
                base_out = sql_parser::StringRef{ref.ptr + i + 1, ref.len - i - 1};
                return true;
            }
        }
        return false;
    }

    static bool matches_table_qualifier(const TableInfo* table,
                                        sql_parser::StringRef qualifier) {
        if (!table || !qualifier.ptr) return false;
        if (table->alias.ptr && table->alias.len > 0 &&
            table->alias.equals_ci(qualifier.ptr, qualifier.len)) {
            return true;
        }
        return table->table_name.equals_ci(qualifier.ptr, qualifier.len);
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_JOIN_OP_H
