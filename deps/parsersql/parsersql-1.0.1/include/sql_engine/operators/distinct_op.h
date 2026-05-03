#ifndef SQL_ENGINE_OPERATORS_DISTINCT_OP_H
#define SQL_ENGINE_OPERATORS_DISTINCT_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/engine_limits.h"
#include <unordered_set>
#include <string>

namespace sql_engine {

class DistinctOperator : public Operator {
public:
    explicit DistinctOperator(Operator* child)
        : child_(child) {}

    void open() override {
        child_->open();
        seen_.clear();
    }

    bool next(Row& out) override {
        while (child_->next(out)) {
            std::string key = row_key(out);
            // Cap distinct row count to prevent unbounded seen_ set.
            if (seen_.find(key) == seen_.end()) {
                check_operator_row_limit(seen_.size(), kDefaultMaxOperatorRows, "DistinctOperator");
            }
            if (seen_.insert(key).second) {
                return true;
            }
        }
        return false;
    }

    void close() override {
        child_->close();
        seen_.clear();
    }

private:
    Operator* child_;
    std::unordered_set<std::string> seen_;

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

#endif // SQL_ENGINE_OPERATORS_DISTINCT_OP_H
