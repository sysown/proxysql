#ifndef SQL_ENGINE_OPERATORS_PROJECT_OP_H
#define SQL_ENGINE_OPERATORS_PROJECT_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/catalog.h"
#include "sql_engine/subquery_executor.h"
#include "sql_parser/arena.h"
#include <functional>
#include <vector>

namespace sql_engine {

template <sql_parser::Dialect D>
class ProjectOperator : public Operator {
public:
    ProjectOperator(Operator* child,
                    const sql_parser::AstNode** exprs,
                    uint16_t expr_count,
                    const Catalog& catalog,
                    const std::vector<const TableInfo*>& tables,
                    FunctionRegistry<D>& functions,
                    sql_parser::Arena& arena,
                    SubqueryExecutor<D>* subquery_exec = nullptr,
                    const std::function<Value(sql_parser::StringRef)>& outer_resolver = {})
        : child_(child), exprs_(exprs), expr_count_(expr_count),
          catalog_(catalog), tables_(tables), functions_(functions), arena_(arena),
          subquery_exec_(subquery_exec), outer_resolver_(outer_resolver) {}

    void open() override {
        if (child_) child_->open();
        no_from_done_ = false;
    }

    bool next(Row& out) override {
        if (!child_) {
            // No FROM clause: produce one row
            if (no_from_done_) return false;
            no_from_done_ = true;
            Row dummy{};
            dummy.values = nullptr;
            dummy.column_count = 0;
            return evaluate_project(dummy, out);
        }

        Row input{};
        if (!child_->next(input)) return false;
        return evaluate_project(input, out);
    }

    void close() override {
        if (child_) child_->close();
    }

private:
    Operator* child_;
    const sql_parser::AstNode** exprs_;
    uint16_t expr_count_;
    const Catalog& catalog_;
    std::vector<const TableInfo*> tables_;
    FunctionRegistry<D>& functions_;
    sql_parser::Arena& arena_;
    SubqueryExecutor<D>* subquery_exec_ = nullptr;
    std::function<Value(sql_parser::StringRef)> outer_resolver_;
    bool no_from_done_ = false;

    bool evaluate_project(const Row& input, Row& out) {
        out = make_row(arena_, expr_count_);
        auto resolver = make_multi_table_resolver(input);
        for (uint16_t i = 0; i < expr_count_; ++i) {
            out.set(i, evaluate_expression<D>(exprs_[i], resolver, functions_, arena_, subquery_exec_));
        }
        return true;
    }

    std::function<Value(sql_parser::StringRef)> make_multi_table_resolver(const Row& row) {
        return [this, &row](sql_parser::StringRef col_name) -> Value {
            uint16_t offset = 0;

            // Check for qualified name (table.column or alias.column)
            const char* dot = nullptr;
            for (uint32_t i = 0; i < col_name.len; ++i) {
                if (col_name.ptr[i] == '.') { dot = col_name.ptr + i; break; }
            }

            if (dot) {
                // Qualified: extract table prefix and column suffix
                uint32_t prefix_len = static_cast<uint32_t>(dot - col_name.ptr);
                sql_parser::StringRef prefix{col_name.ptr, prefix_len};
                sql_parser::StringRef suffix{dot + 1, col_name.len - prefix_len - 1};

                for (const auto* table : tables_) {
                    if (!table) continue;
                    if (table->table_name.equals_ci(prefix.ptr, prefix.len) ||
                        (table->alias.ptr && table->alias.equals_ci(prefix.ptr, prefix.len))) {
                        const ColumnInfo* col = catalog_.get_column(table, suffix);
                        if (col) {
                            uint16_t idx = offset + col->ordinal;
                            if (idx < row.column_count) return row.get(idx);
                        }
                    }
                    offset += table->column_count;
                }
            } else {
                // Unqualified: try all tables
                for (const auto* table : tables_) {
                    if (!table) continue;
                    const ColumnInfo* col = catalog_.get_column(table, col_name);
                    if (col) {
                        uint16_t idx = offset + col->ordinal;
                        if (idx < row.column_count) return row.get(idx);
                    }
                    offset += table->column_count;
                }
            }

            // Fall back to outer resolver for correlated subqueries
            if (outer_resolver_) {
                return outer_resolver_(col_name);
            }
            return value_null();
        };
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_PROJECT_OP_H
