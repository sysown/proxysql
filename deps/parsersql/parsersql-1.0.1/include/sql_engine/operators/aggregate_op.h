#ifndef SQL_ENGINE_OPERATORS_AGGREGATE_OP_H
#define SQL_ENGINE_OPERATORS_AGGREGATE_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/catalog.h"
#include "sql_engine/engine_limits.h"
#include "sql_parser/arena.h"
#include <functional>
#include <vector>
#include <unordered_map>
#include <string>
#include <cstring>
#include <cmath>

namespace sql_engine {

template <sql_parser::Dialect D>
class AggregateOperator : public Operator {
public:
    AggregateOperator(Operator* child,
                      const sql_parser::AstNode** group_by_exprs,
                      uint16_t group_count,
                      const sql_parser::AstNode** agg_exprs,
                      uint16_t agg_count,
                      const Catalog& catalog,
                      const std::vector<const TableInfo*>& tables,
                      FunctionRegistry<D>& functions,
                      sql_parser::Arena& arena)
        : child_(child), group_by_exprs_(group_by_exprs), group_count_(group_count),
          agg_exprs_(agg_exprs), agg_count_(agg_count),
          catalog_(catalog), tables_(tables), functions_(functions), arena_(arena) {}

    void open() override {
        child_->open();
        groups_.clear();
        group_order_.clear();
        result_idx_ = 0;

        // Consume all child rows
        Row row{};
        while (child_->next(row)) {
            auto resolver = make_resolver(row);
            std::string key = compute_group_key(resolver);

            auto it = groups_.find(key);
            if (it == groups_.end()) {
                // Cap distinct group count to prevent unbounded memory.
                check_operator_row_limit(groups_.size(), kDefaultMaxOperatorRows, "AggregateOperator");
                GroupState state;
                state.group_values.reserve(group_count_);
                for (uint16_t i = 0; i < group_count_; ++i) {
                    state.group_values.push_back(evaluate_expression<D>(
                        group_by_exprs_[i], resolver, functions_, arena_));
                }
                state.agg_states.reserve(agg_count_);
                for (uint16_t i = 0; i < agg_count_; ++i) {
                    AggState s{};
                    detect_agg_type(agg_exprs_[i], s);
                    state.agg_states.push_back(s);
                }
                groups_[key] = std::move(state);
                group_order_.push_back(key);
                it = groups_.find(key);
            }

            // Update aggregate states
            auto resolver2 = make_resolver(row);
            for (uint16_t i = 0; i < agg_count_; ++i) {
                update_agg(it->second.agg_states[i], agg_exprs_[i], resolver2);
            }
        }
        child_->close();
    }

    bool next(Row& out) override {
        if (result_idx_ >= group_order_.size()) {
            // If no groups at all and no group-by (whole-table aggregate), emit one row
            if (result_idx_ == 0 && group_count_ == 0 && groups_.empty()) {
                result_idx_ = 1; // only once
                uint16_t cols = group_count_ + agg_count_;
                if (cols == 0) return false;
                out = make_row(arena_, cols);
                for (uint16_t i = 0; i < agg_count_; ++i) {
                    AggState s{};
                    detect_agg_type(agg_exprs_[i], s);
                    out.set(group_count_ + i, finalize_agg(s));
                }
                return true;
            }
            return false;
        }

        const auto& key = group_order_[result_idx_++];
        const auto& state = groups_[key];

        uint16_t cols = group_count_ + agg_count_;
        out = make_row(arena_, cols);
        for (uint16_t i = 0; i < group_count_; ++i) {
            out.set(i, state.group_values[i]);
        }
        for (uint16_t i = 0; i < agg_count_; ++i) {
            out.set(group_count_ + i, finalize_agg(state.agg_states[i]));
        }
        return true;
    }

    void close() override {
        groups_.clear();
        group_order_.clear();
    }

private:
    Operator* child_;
    const sql_parser::AstNode** group_by_exprs_;
    uint16_t group_count_;
    const sql_parser::AstNode** agg_exprs_;
    uint16_t agg_count_;
    const Catalog& catalog_;
    std::vector<const TableInfo*> tables_;
    FunctionRegistry<D>& functions_;
    sql_parser::Arena& arena_;

    enum class AggType { COUNT, SUM, AVG, MIN, MAX, EXPR };

    struct AggState {
        AggType type = AggType::EXPR;
        int64_t count = 0;
        double sum = 0.0;
        Value min_val{};
        Value max_val{};
        bool has_value = false;
        bool count_star = false; // COUNT(*)
    };

    struct GroupState {
        std::vector<Value> group_values;
        std::vector<AggState> agg_states;
    };

    std::unordered_map<std::string, GroupState> groups_;
    std::vector<std::string> group_order_;
    size_t result_idx_ = 0;

    std::function<Value(sql_parser::StringRef)> make_resolver(const Row& row) {
        return [this, &row](sql_parser::StringRef col_name) -> Value {
            uint16_t offset = 0;
            for (const auto* table : tables_) {
                if (!table) continue;
                const ColumnInfo* col = catalog_.get_column(table, col_name);
                if (col) {
                    uint16_t idx = offset + col->ordinal;
                    if (idx < row.column_count) return row.get(idx);
                }
                offset += table->column_count;
            }
            return value_null();
        };
    }

    std::string compute_group_key(const std::function<Value(sql_parser::StringRef)>& resolver) {
        if (group_count_ == 0) return "";
        std::string key;
        for (uint16_t i = 0; i < group_count_; ++i) {
            Value v = evaluate_expression<D>(group_by_exprs_[i], resolver, functions_, arena_);
            key += value_to_string(v);
            key += '\x01'; // separator
        }
        return key;
    }

    static std::string value_to_string(const Value& v) {
        if (v.is_null()) return "NULL";
        switch (v.tag) {
            case Value::TAG_BOOL: return v.bool_val ? "1" : "0";
            case Value::TAG_INT64: return std::to_string(v.int_val);
            case Value::TAG_UINT64: return std::to_string(v.uint_val);
            case Value::TAG_DOUBLE: return std::to_string(v.double_val);
            case Value::TAG_STRING: return std::string(v.str_val.ptr, v.str_val.len);
            default: return "?";
        }
    }

    void detect_agg_type(const sql_parser::AstNode* expr, AggState& state) {
        if (!expr) { state.type = AggType::EXPR; return; }

        if (expr->type == sql_parser::NodeType::NODE_FUNCTION_CALL) {
            sql_parser::StringRef name = expr->value();
            if (name.equals_ci("COUNT", 5)) {
                state.type = AggType::COUNT;
                // Check for COUNT(*)
                const sql_parser::AstNode* arg = expr->first_child;
                if (arg && arg->type == sql_parser::NodeType::NODE_ASTERISK) {
                    state.count_star = true;
                }
                return;
            }
            if (name.equals_ci("SUM", 3)) { state.type = AggType::SUM; return; }
            if (name.equals_ci("AVG", 3)) { state.type = AggType::AVG; return; }
            if (name.equals_ci("MIN", 3)) { state.type = AggType::MIN; return; }
            if (name.equals_ci("MAX", 3)) { state.type = AggType::MAX; return; }
        }
        state.type = AggType::EXPR;
    }

    void update_agg(AggState& state, const sql_parser::AstNode* expr,
                    const std::function<Value(sql_parser::StringRef)>& resolver) {
        switch (state.type) {
            case AggType::COUNT: {
                if (state.count_star) {
                    state.count++;
                } else {
                    // COUNT(expr) - count non-null values
                    const sql_parser::AstNode* arg = expr->first_child;
                    Value v = evaluate_expression<D>(arg, resolver, functions_, arena_);
                    if (!v.is_null()) state.count++;
                }
                break;
            }
            case AggType::SUM:
            case AggType::AVG: {
                const sql_parser::AstNode* arg = expr->first_child;
                Value v = evaluate_expression<D>(arg, resolver, functions_, arena_);
                if (!v.is_null()) {
                    state.sum += v.to_double();
                    state.count++;
                    state.has_value = true;
                }
                break;
            }
            case AggType::MIN: {
                const sql_parser::AstNode* arg = expr->first_child;
                Value v = evaluate_expression<D>(arg, resolver, functions_, arena_);
                if (!v.is_null()) {
                    if (!state.has_value || compare_values(v, state.min_val) < 0) {
                        state.min_val = v;
                        state.has_value = true;
                    }
                }
                break;
            }
            case AggType::MAX: {
                const sql_parser::AstNode* arg = expr->first_child;
                Value v = evaluate_expression<D>(arg, resolver, functions_, arena_);
                if (!v.is_null()) {
                    if (!state.has_value || compare_values(v, state.max_val) > 0) {
                        state.max_val = v;
                        state.has_value = true;
                    }
                }
                break;
            }
            case AggType::EXPR:
                break;
        }
    }

    Value finalize_agg(const AggState& state) const {
        switch (state.type) {
            case AggType::COUNT:
                return value_int(state.count);
            case AggType::SUM:
                if (!state.has_value) return value_null();
                return value_double(state.sum);
            case AggType::AVG:
                if (state.count == 0) return value_null();
                return value_double(state.sum / static_cast<double>(state.count));
            case AggType::MIN:
                if (!state.has_value) return value_null();
                return state.min_val;
            case AggType::MAX:
                if (!state.has_value) return value_null();
                return state.max_val;
            case AggType::EXPR:
                return value_null();
        }
        return value_null();
    }

    static int compare_values(const Value& a, const Value& b) {
        if (a.is_null() && b.is_null()) return 0;
        if (a.is_null()) return -1;
        if (b.is_null()) return 1;

        // Try numeric comparison
        if (a.is_numeric() && b.is_numeric()) {
            double da = a.to_double();
            double db = b.to_double();
            if (da < db) return -1;
            if (da > db) return 1;
            return 0;
        }

        // String comparison
        if (a.tag == Value::TAG_STRING && b.tag == Value::TAG_STRING) {
            uint32_t minlen = a.str_val.len < b.str_val.len ? a.str_val.len : b.str_val.len;
            int cmp = std::memcmp(a.str_val.ptr, b.str_val.ptr, minlen);
            if (cmp != 0) return cmp;
            if (a.str_val.len < b.str_val.len) return -1;
            if (a.str_val.len > b.str_val.len) return 1;
            return 0;
        }

        return 0;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_AGGREGATE_OP_H
