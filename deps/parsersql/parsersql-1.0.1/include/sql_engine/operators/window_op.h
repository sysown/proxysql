#ifndef SQL_ENGINE_OPERATORS_WINDOW_OP_H
#define SQL_ENGINE_OPERATORS_WINDOW_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/expression_eval.h"
#include "sql_engine/catalog.h"
#include "sql_engine/engine_limits.h"
#include "sql_parser/arena.h"
#include <functional>
#include <vector>
#include <algorithm>
#include <string>
#include <cstring>
#include <cmath>

namespace sql_engine {

// WindowOperator: materializes all child rows, computes window function values,
// and yields rows with the original columns plus window function results appended.
// The final output has select_count columns (matching the SELECT list), where
// non-window expressions are evaluated from the source row, and window expressions
// are replaced with their computed values.
template <sql_parser::Dialect D>
class WindowOperator : public Operator {
public:
    WindowOperator(Operator* child,
                   const sql_parser::AstNode** window_exprs,
                   uint16_t window_count,
                   const sql_parser::AstNode** select_exprs,
                   uint16_t select_count,
                   const Catalog& catalog,
                   const std::vector<const TableInfo*>& tables,
                   FunctionRegistry<D>& functions,
                   sql_parser::Arena& arena)
        : child_(child), window_exprs_(window_exprs), window_count_(window_count),
          select_exprs_(select_exprs), select_count_(select_count),
          catalog_(catalog), tables_(tables), functions_(functions), arena_(arena) {}

    void open() override {
        child_->open();
        buffer_.clear();
        result_rows_.clear();
        cursor_ = 0;

        // 1. Consume all child rows into buffer
        Row row{};
        while (child_->next(row)) {
            check_operator_row_limit(buffer_.size(), kDefaultMaxOperatorRows, "WindowOperator");
            buffer_.push_back(row);
        }
        child_->close();

        if (buffer_.empty()) return;

        // 2. For each window function, compute values for all rows
        // window_values_[w][i] = value of window function w for buffer row i
        size_t n = buffer_.size();
        window_values_.resize(window_count_);
        for (uint16_t w = 0; w < window_count_; ++w) {
            window_values_[w].assign(n, value_null());
            compute_window_function(w);
        }

        // 3. Build result rows: evaluate each select expression
        for (size_t i = 0; i < n; ++i) {
            Row out = make_row(arena_, select_count_);
            auto resolver = make_resolver(buffer_[i]);
            for (uint16_t s = 0; s < select_count_; ++s) {
                const sql_parser::AstNode* expr = select_exprs_[s];
                if (expr && expr->type == sql_parser::NodeType::NODE_WINDOW_FUNCTION) {
                    // Find which window_exprs_ index this corresponds to
                    for (uint16_t w = 0; w < window_count_; ++w) {
                        if (window_exprs_[w] == expr) {
                            out.set(s, window_values_[w][i]);
                            break;
                        }
                    }
                } else {
                    out.set(s, evaluate_expression<D>(expr, resolver, functions_, arena_));
                }
            }
            result_rows_.push_back(out);
        }
    }

    bool next(Row& out) override {
        if (cursor_ >= result_rows_.size()) return false;
        out = result_rows_[cursor_++];
        return true;
    }

    void close() override {
        buffer_.clear();
        result_rows_.clear();
        window_values_.clear();
        cursor_ = 0;
    }

private:
    Operator* child_;
    const sql_parser::AstNode** window_exprs_;
    uint16_t window_count_;
    const sql_parser::AstNode** select_exprs_;
    uint16_t select_count_;
    const Catalog& catalog_;
    std::vector<const TableInfo*> tables_;
    FunctionRegistry<D>& functions_;
    sql_parser::Arena& arena_;

    std::vector<Row> buffer_;
    std::vector<Row> result_rows_;
    std::vector<std::vector<Value>> window_values_;
    size_t cursor_ = 0;

    // Window function types
    enum class WinFuncType { ROW_NUMBER, RANK, DENSE_RANK, SUM, COUNT, AVG, MIN, MAX, LAG, LEAD, FIRST_VALUE, LAST_VALUE, UNKNOWN };

    WinFuncType detect_func_type(const sql_parser::AstNode* win_node) {
        if (!win_node || win_node->type != sql_parser::NodeType::NODE_WINDOW_FUNCTION)
            return WinFuncType::UNKNOWN;
        const sql_parser::AstNode* func = win_node->first_child;
        if (!func) return WinFuncType::UNKNOWN;
        sql_parser::StringRef name = func->value();
        if (name.equals_ci("ROW_NUMBER", 10)) return WinFuncType::ROW_NUMBER;
        if (name.equals_ci("RANK", 4)) return WinFuncType::RANK;
        if (name.equals_ci("DENSE_RANK", 10)) return WinFuncType::DENSE_RANK;
        if (name.equals_ci("SUM", 3)) return WinFuncType::SUM;
        if (name.equals_ci("COUNT", 5)) return WinFuncType::COUNT;
        if (name.equals_ci("AVG", 3)) return WinFuncType::AVG;
        if (name.equals_ci("MIN", 3)) return WinFuncType::MIN;
        if (name.equals_ci("MAX", 3)) return WinFuncType::MAX;
        if (name.equals_ci("LAG", 3)) return WinFuncType::LAG;
        if (name.equals_ci("LEAD", 4)) return WinFuncType::LEAD;
        if (name.equals_ci("FIRST_VALUE", 11)) return WinFuncType::FIRST_VALUE;
        if (name.equals_ci("LAST_VALUE", 10)) return WinFuncType::LAST_VALUE;
        return WinFuncType::UNKNOWN;
    }

    // Extract PARTITION BY expressions from window spec
    std::vector<const sql_parser::AstNode*> get_partition_exprs(const sql_parser::AstNode* win_node) {
        std::vector<const sql_parser::AstNode*> result;
        const sql_parser::AstNode* spec = win_node->first_child ?
            win_node->first_child->next_sibling : nullptr;
        if (!spec || spec->type != sql_parser::NodeType::NODE_WINDOW_SPEC) return result;
        for (const sql_parser::AstNode* c = spec->first_child; c; c = c->next_sibling) {
            if (c->type == sql_parser::NodeType::NODE_WINDOW_PARTITION) {
                for (const sql_parser::AstNode* e = c->first_child; e; e = e->next_sibling) {
                    result.push_back(e);
                }
            }
        }
        return result;
    }

    // Extract ORDER BY items from window spec
    struct OrderItem {
        const sql_parser::AstNode* expr;
        bool desc;
    };

    std::vector<OrderItem> get_order_items(const sql_parser::AstNode* win_node) {
        std::vector<OrderItem> result;
        const sql_parser::AstNode* spec = win_node->first_child ?
            win_node->first_child->next_sibling : nullptr;
        if (!spec || spec->type != sql_parser::NodeType::NODE_WINDOW_SPEC) return result;
        for (const sql_parser::AstNode* c = spec->first_child; c; c = c->next_sibling) {
            if (c->type == sql_parser::NodeType::NODE_WINDOW_ORDER) {
                for (const sql_parser::AstNode* item = c->first_child; item; item = item->next_sibling) {
                    if (item->type == sql_parser::NodeType::NODE_ORDER_BY_ITEM) {
                        OrderItem oi;
                        oi.expr = item->first_child;
                        oi.desc = false;
                        // Check for DESC
                        for (const sql_parser::AstNode* ch = item->first_child; ch; ch = ch->next_sibling) {
                            if (ch->type == sql_parser::NodeType::NODE_IDENTIFIER) {
                                sql_parser::StringRef dir = ch->value();
                                if (dir.equals_ci("DESC", 4)) oi.desc = true;
                            }
                        }
                        result.push_back(oi);
                    }
                }
            }
        }
        return result;
    }

    std::function<Value(sql_parser::StringRef)> make_resolver(const Row& row) {
        return [this, &row](sql_parser::StringRef col_name) -> Value {
            uint16_t offset = 0;
            // Check for qualified name
            const char* dot = nullptr;
            for (uint32_t i = 0; i < col_name.len; ++i) {
                if (col_name.ptr[i] == '.') { dot = col_name.ptr + i; break; }
            }
            if (dot) {
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
            return value_null();
        };
    }

    // Evaluate an expression against a specific row
    Value eval_for_row(const sql_parser::AstNode* expr, size_t row_idx) {
        auto resolver = make_resolver(buffer_[row_idx]);
        return evaluate_expression<D>(expr, resolver, functions_, arena_);
    }

    // Build a partition key string for a row
    std::string partition_key(const std::vector<const sql_parser::AstNode*>& part_exprs, size_t row_idx) {
        if (part_exprs.empty()) return "";
        std::string key;
        for (auto* expr : part_exprs) {
            Value v = eval_for_row(expr, row_idx);
            key += value_to_string(v);
            key += '\x01';
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

    // Build sort key for ordering rows
    std::string order_key(const std::vector<OrderItem>& order_items, size_t row_idx) {
        if (order_items.empty()) return "";
        std::string key;
        for (auto& item : order_items) {
            Value v = eval_for_row(item.expr, row_idx);
            key += value_to_string(v);
            key += '\x01';
        }
        return key;
    }

    void compute_window_function(uint16_t w) {
        const sql_parser::AstNode* win_node = window_exprs_[w];
        WinFuncType func_type = detect_func_type(win_node);
        auto part_exprs = get_partition_exprs(win_node);
        auto order_items = get_order_items(win_node);

        size_t n = buffer_.size();

        // Build sorted indices by PARTITION BY + ORDER BY
        std::vector<size_t> indices(n);
        for (size_t i = 0; i < n; ++i) indices[i] = i;

        // Sort: first by partition key, then by order key
        std::sort(indices.begin(), indices.end(), [&](size_t a, size_t b) {
            // Compare partition keys
            if (!part_exprs.empty()) {
                for (auto* pe : part_exprs) {
                    Value va = eval_for_row(pe, a);
                    Value vb = eval_for_row(pe, b);
                    int cmp = compare_values(va, vb);
                    if (cmp != 0) return cmp < 0;
                }
            }
            // Compare order keys
            for (auto& oi : order_items) {
                Value va = eval_for_row(oi.expr, a);
                Value vb = eval_for_row(oi.expr, b);
                int cmp = compare_values(va, vb);
                if (cmp != 0) return oi.desc ? (cmp > 0) : (cmp < 0);
            }
            return false; // stable
        });

        // Now walk sorted indices, track partitions, compute values
        // We need to assign values back to original buffer positions
        std::vector<Value> sorted_values(n, value_null());

        // Get the function node's first argument expression
        const sql_parser::AstNode* func_node = win_node->first_child;
        const sql_parser::AstNode* func_arg = func_node ? func_node->first_child : nullptr;
        bool is_count_star = (func_type == WinFuncType::COUNT && func_arg &&
                              func_arg->type == sql_parser::NodeType::NODE_ASTERISK);

        // Get LAG/LEAD offset (default 1)
        int64_t lag_lead_offset = 1;
        if (func_type == WinFuncType::LAG || func_type == WinFuncType::LEAD) {
            // Second argument is the offset
            if (func_arg && func_arg->next_sibling) {
                Value off_val = eval_for_row(func_arg->next_sibling, indices[0]);
                if (!off_val.is_null()) lag_lead_offset = off_val.to_int64();
            }
        }

        size_t part_start = 0;
        for (size_t i = 0; i <= n; ++i) {
            bool new_partition = (i == n);
            if (!new_partition && i > 0) {
                std::string pk_cur = partition_key(part_exprs, indices[i]);
                std::string pk_prev = partition_key(part_exprs, indices[i-1]);
                if (pk_cur != pk_prev) new_partition = true;
            }

            if (new_partition) {
                size_t part_end = i;
                size_t part_size = part_end - part_start;

                // Process this partition [part_start, part_end)
                switch (func_type) {
                    case WinFuncType::ROW_NUMBER:
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = value_int(static_cast<int64_t>(j - part_start + 1));
                        }
                        break;

                    case WinFuncType::RANK: {
                        int64_t rank = 1;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (j > part_start) {
                                std::string ok_cur = order_key(order_items, indices[j]);
                                std::string ok_prev = order_key(order_items, indices[j-1]);
                                if (ok_cur != ok_prev) {
                                    rank = static_cast<int64_t>(j - part_start + 1);
                                }
                            }
                            sorted_values[j] = value_int(rank);
                        }
                        break;
                    }

                    case WinFuncType::DENSE_RANK: {
                        int64_t rank = 1;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (j > part_start) {
                                std::string ok_cur = order_key(order_items, indices[j]);
                                std::string ok_prev = order_key(order_items, indices[j-1]);
                                if (ok_cur != ok_prev) {
                                    rank++;
                                }
                            }
                            sorted_values[j] = value_int(rank);
                        }
                        break;
                    }

                    case WinFuncType::SUM: {
                        double sum = 0.0;
                        bool has_val = false;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (func_arg) {
                                Value v = eval_for_row(func_arg, indices[j]);
                                if (!v.is_null()) { sum += v.to_double(); has_val = true; }
                            }
                        }
                        Value result = has_val ? value_double(sum) : value_null();
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = result;
                        }
                        break;
                    }

                    case WinFuncType::COUNT: {
                        int64_t count = 0;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (is_count_star) {
                                count++;
                            } else if (func_arg) {
                                Value v = eval_for_row(func_arg, indices[j]);
                                if (!v.is_null()) count++;
                            }
                        }
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = value_int(count);
                        }
                        break;
                    }

                    case WinFuncType::AVG: {
                        double sum = 0.0;
                        int64_t count = 0;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (func_arg) {
                                Value v = eval_for_row(func_arg, indices[j]);
                                if (!v.is_null()) { sum += v.to_double(); count++; }
                            }
                        }
                        Value result = (count > 0) ? value_double(sum / static_cast<double>(count)) : value_null();
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = result;
                        }
                        break;
                    }

                    case WinFuncType::MIN: {
                        Value min_val = value_null();
                        bool has_val = false;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (func_arg) {
                                Value v = eval_for_row(func_arg, indices[j]);
                                if (!v.is_null()) {
                                    if (!has_val || compare_values(v, min_val) < 0) min_val = v;
                                    has_val = true;
                                }
                            }
                        }
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = min_val;
                        }
                        break;
                    }

                    case WinFuncType::MAX: {
                        Value max_val = value_null();
                        bool has_val = false;
                        for (size_t j = part_start; j < part_end; ++j) {
                            if (func_arg) {
                                Value v = eval_for_row(func_arg, indices[j]);
                                if (!v.is_null()) {
                                    if (!has_val || compare_values(v, max_val) > 0) max_val = v;
                                    has_val = true;
                                }
                            }
                        }
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = max_val;
                        }
                        break;
                    }

                    case WinFuncType::LAG: {
                        for (size_t j = part_start; j < part_end; ++j) {
                            int64_t src = static_cast<int64_t>(j) - lag_lead_offset;
                            if (src >= static_cast<int64_t>(part_start) && src < static_cast<int64_t>(part_end) && func_arg) {
                                sorted_values[j] = eval_for_row(func_arg, indices[static_cast<size_t>(src)]);
                            } else {
                                sorted_values[j] = value_null();
                            }
                        }
                        break;
                    }

                    case WinFuncType::LEAD: {
                        for (size_t j = part_start; j < part_end; ++j) {
                            int64_t src = static_cast<int64_t>(j) + lag_lead_offset;
                            if (src >= static_cast<int64_t>(part_start) && src < static_cast<int64_t>(part_end) && func_arg) {
                                sorted_values[j] = eval_for_row(func_arg, indices[static_cast<size_t>(src)]);
                            } else {
                                sorted_values[j] = value_null();
                            }
                        }
                        break;
                    }

                    case WinFuncType::FIRST_VALUE: {
                        Value first = value_null();
                        if (func_arg && part_size > 0) {
                            first = eval_for_row(func_arg, indices[part_start]);
                        }
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = first;
                        }
                        break;
                    }

                    case WinFuncType::LAST_VALUE: {
                        Value last = value_null();
                        if (func_arg && part_size > 0) {
                            last = eval_for_row(func_arg, indices[part_end - 1]);
                        }
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = last;
                        }
                        break;
                    }

                    case WinFuncType::UNKNOWN:
                        for (size_t j = part_start; j < part_end; ++j) {
                            sorted_values[j] = value_null();
                        }
                        break;
                }

                part_start = i;
            }
        }

        // Map sorted values back to original buffer order
        for (size_t i = 0; i < n; ++i) {
            window_values_[w][indices[i]] = sorted_values[i];
        }
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_WINDOW_OP_H
