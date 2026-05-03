#ifndef SQL_ENGINE_OPERATORS_SET_OP_OP_H
#define SQL_ENGINE_OPERATORS_SET_OP_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/plan_node.h"
#include "sql_engine/thread_pool.h"
#include "sql_engine/engine_limits.h"
#include <unordered_set>
#include <string>
#include <vector>
#include <future>
#include <stdexcept>

namespace sql_engine {

class SetOpOperator : public Operator {
public:
    SetOpOperator(Operator* left, Operator* right, uint8_t op, bool all,
                  bool parallel_open = false, ThreadPool* pool = nullptr)
        : left_(left), right_(right), op_(op), all_(all),
          parallel_open_(parallel_open), pool_(pool) {}

    void open() override {
        if (parallel_open_ && pool_) {
            // Thread-pool parallel open: ~1-2us dispatch vs ~200us for std::async
            auto fl = pool_->submit([this]{ left_->open(); });
            auto fr = pool_->submit([this]{ right_->open(); });
            fl.get();
            fr.get();
        } else if (parallel_open_) {
            // Fallback: std::async when no pool available
            auto fl = std::async(std::launch::async, [this]{ left_->open(); });
            auto fr = std::async(std::launch::async, [this]{ right_->open(); });
            fl.get();
            fr.get();
        } else {
            left_->open();
            right_->open();
        }
        reading_left_ = true;
        seen_.clear();
        expected_col_count_ = -1;

        if (op_ == SET_OP_INTERSECT || op_ == SET_OP_EXCEPT) {
            // Materialize right side into a set
            right_set_.clear();
            Row r{};
            while (right_->next(r)) {
                check_col_count(r);
                check_operator_row_limit(right_set_.size(), kDefaultMaxOperatorRows, "SetOpOperator");
                right_set_.insert(row_key(r));
            }
            right_->close();
        }
    }

    bool next(Row& out) override {
        if (op_ == SET_OP_UNION && !all_) {
            // UNION (deduplicated)
            while (true) {
                bool got = false;
                if (reading_left_) {
                    got = left_->next(out);
                    if (!got) { reading_left_ = false; }
                }
                if (!reading_left_) {
                    got = right_->next(out);
                    if (!got) return false;
                }
                if (got) {
                    check_col_count(out);
                    std::string key = row_key(out);
                    if (seen_.find(key) == seen_.end()) {
                        check_operator_row_limit(seen_.size(), kDefaultMaxOperatorRows, "SetOpOperator");
                    }
                    if (seen_.insert(key).second) return true;
                }
            }
        }

        if (op_ == SET_OP_UNION && all_) {
            // UNION ALL: yield left then right
            if (reading_left_) {
                if (left_->next(out)) {
                    check_col_count(out);
                    return true;
                }
                reading_left_ = false;
            }
            if (right_->next(out)) {
                check_col_count(out);
                return true;
            }
            return false;
        }

        if (op_ == SET_OP_INTERSECT) {
            // Yield left rows that also appear in right
            while (left_->next(out)) {
                check_col_count(out);
                std::string key = row_key(out);
                if (right_set_.count(key)) {
                    if (all_ || seen_.insert(key).second)
                        return true;
                }
            }
            return false;
        }

        if (op_ == SET_OP_EXCEPT) {
            // Yield left rows that don't appear in right
            while (left_->next(out)) {
                check_col_count(out);
                std::string key = row_key(out);
                if (!right_set_.count(key)) {
                    if (all_ || seen_.insert(key).second)
                        return true;
                }
            }
            return false;
        }

        return false;
    }

    void close() override {
        left_->close();
        right_->close();
        seen_.clear();
        right_set_.clear();
    }

private:
    Operator* left_;
    Operator* right_;
    uint8_t op_;
    bool all_;
    bool parallel_open_;
    ThreadPool* pool_ = nullptr;
    bool reading_left_ = true;
    std::unordered_set<std::string> seen_;
    std::unordered_set<std::string> right_set_;
    // Column count established by the first row we see. Used to detect
    // schema mismatches between the two sides of a UNION/INTERSECT/EXCEPT --
    // which the SQL standard says must have the same number of columns.
    // Previously, mismatched column counts silently produced wrong results
    // because row_key() would iterate a different number of values on each
    // side. Now we throw a clear error at execution time.
    int16_t expected_col_count_ = -1;

    void check_col_count(const Row& row) {
        if (expected_col_count_ < 0) {
            expected_col_count_ = static_cast<int16_t>(row.column_count);
            return;
        }
        if (row.column_count != static_cast<uint16_t>(expected_col_count_)) {
            throw std::runtime_error(
                "set operation column count mismatch: expected " +
                std::to_string(expected_col_count_) + " columns, got " +
                std::to_string(row.column_count));
        }
    }

    static std::string row_key(const Row& row) {
        std::string key;
        for (uint16_t i = 0; i < row.column_count; ++i) {
            const Value& v = row.values[i];
            if (v.is_null()) {
                key += "N";
            } else {
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
            key += '\x01';
        }
        return key;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_SET_OP_OP_H
