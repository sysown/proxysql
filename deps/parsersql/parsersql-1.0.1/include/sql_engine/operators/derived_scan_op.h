// derived_scan_op.h -- DerivedScanOperator for subqueries in FROM clause
//
// Materializes the inner plan's result set on open(), then yields
// rows one at a time from the materialized buffer on next().
// Deep-copies all row data into the outer arena to avoid dangling
// pointers into arenas that may be reset after inner execution.

#ifndef SQL_ENGINE_OPERATORS_DERIVED_SCAN_OP_H
#define SQL_ENGINE_OPERATORS_DERIVED_SCAN_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/row.h"
#include "sql_parser/arena.h"
#include <vector>
#include <cstring>

namespace sql_engine {

class DerivedScanOperator : public Operator {
public:
    // Takes the inner operator and an arena for deep-copying row data.
    // The arena must outlive any result set produced by the outer query.
    DerivedScanOperator(Operator* inner, sql_parser::Arena& arena)
        : inner_(inner), arena_(arena) {}

    void open() override {
        rows_.clear();
        cursor_ = 0;
        if (inner_) {
            inner_->open();
            Row row{};
            while (inner_->next(row)) {
                rows_.push_back(deep_copy_row(row));
            }
            inner_->close();
        }
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
    Operator* inner_;
    sql_parser::Arena& arena_;
    std::vector<Row> rows_;
    size_t cursor_ = 0;

    Row deep_copy_row(const Row& src) {
        if (!src.values || src.column_count == 0) {
            Row result;
            result.values = nullptr;
            result.column_count = 0;
            return result;
        }
        uint16_t cc = src.column_count;
        Row result = make_row(arena_, cc);
        for (uint16_t i = 0; i < cc; ++i) {
            Value v = src.values[i];
            // Deep-copy string data into the arena
            if ((v.tag == Value::TAG_STRING ||
                 v.tag == Value::TAG_DECIMAL ||
                 v.tag == Value::TAG_BYTES ||
                 v.tag == Value::TAG_JSON) &&
                v.str_val.ptr && v.str_val.len > 0) {
                char* buf = static_cast<char*>(arena_.allocate(v.str_val.len));
                std::memcpy(buf, v.str_val.ptr, v.str_val.len);
                v.str_val.ptr = buf;
            }
            result.set(i, v);
        }
        return result;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_DERIVED_SCAN_OP_H
