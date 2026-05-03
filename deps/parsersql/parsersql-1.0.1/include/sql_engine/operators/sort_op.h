#ifndef SQL_ENGINE_OPERATORS_SORT_OP_H
#define SQL_ENGINE_OPERATORS_SORT_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/catalog.h"
#include "sql_engine/engine_limits.h"
#include "sql_parser/arena.h"
#include <algorithm>
#include <functional>
#include <vector>
#include <cstring>

namespace sql_engine {

template <sql_parser::Dialect D>
class SortOperator : public Operator {
public:
    SortOperator(Operator* child,
                 const sql_parser::AstNode** keys,
                 const uint8_t* directions,
                 uint16_t key_count,
                 const Catalog& catalog,
                 const std::vector<const TableInfo*>& tables,
                 FunctionRegistry<D>& functions,
                 sql_parser::Arena& arena)
        : child_(child), keys_(keys), directions_(directions), key_count_(key_count),
          catalog_(catalog), tables_(tables), functions_(functions), arena_(arena) {}

    void open() override {
        child_->open();
        rows_.clear();
        cursor_ = 0;

        Row row{};
        while (child_->next(row)) {
            // Hard cap to prevent unbounded materialization (no spill yet).
            check_operator_row_limit(rows_.size(), kDefaultMaxOperatorRows, "SortOperator");
            rows_.push_back(row);
        }
        child_->close();

        // Sort using key expressions
        std::stable_sort(rows_.begin(), rows_.end(),
            [this](const Row& a, const Row& b) -> bool {
                for (uint16_t i = 0; i < key_count_; ++i) {
                    auto resolver_a = make_resolver(a);
                    auto resolver_b = make_resolver(b);
                    Value va = evaluate_expression<D>(keys_[i], resolver_a, functions_, arena_);
                    Value vb = evaluate_expression<D>(keys_[i], resolver_b, functions_, arena_);
                    int cmp = compare_values(va, vb);
                    if (cmp == 0) continue;
                    bool asc = (directions_[i] == 0);
                    return asc ? (cmp < 0) : (cmp > 0);
                }
                return false;
            });
    }

    bool next(Row& out) override {
        if (cursor_ >= rows_.size()) return false;
        out = rows_[cursor_++];
        return true;
    }

    void close() override {
        rows_.clear();
        cursor_ = 0;
    }

private:
    Operator* child_;
    const sql_parser::AstNode** keys_;
    const uint8_t* directions_;
    uint16_t key_count_;
    const Catalog& catalog_;
    std::vector<const TableInfo*> tables_;
    FunctionRegistry<D>& functions_;
    sql_parser::Arena& arena_;

    std::vector<Row> rows_;
    size_t cursor_ = 0;

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

    static int compare_values(const Value& a, const Value& b) {
        if (a.is_null() && b.is_null()) return 0;
        if (a.is_null()) return -1;
        if (b.is_null()) return 1;

        if (a.is_numeric() && b.is_numeric()) {
            double da = a.to_double();
            double db = b.to_double();
            if (da < db) return -1;
            if (da > db) return 1;
            return 0;
        }

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

#endif // SQL_ENGINE_OPERATORS_SORT_OP_H
