#ifndef SQL_ENGINE_OPERATORS_LIMIT_OP_H
#define SQL_ENGINE_OPERATORS_LIMIT_OP_H

#include "sql_engine/operator.h"
#include <cstdint>

namespace sql_engine {

class LimitOperator : public Operator {
public:
    LimitOperator(Operator* child, int64_t count, int64_t offset)
        : child_(child), count_(count), offset_(offset) {}

    void open() override {
        child_->open();
        emitted_ = 0;
        skipped_ = 0;
    }

    bool next(Row& out) override {
        // Skip offset rows
        while (skipped_ < offset_) {
            if (!child_->next(out)) return false;
            skipped_++;
        }
        // Check count
        if (count_ >= 0 && emitted_ >= count_) return false;
        if (!child_->next(out)) return false;
        emitted_++;
        return true;
    }

    void close() override {
        child_->close();
    }

private:
    Operator* child_;
    int64_t count_;
    int64_t offset_;
    int64_t emitted_ = 0;
    int64_t skipped_ = 0;
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_LIMIT_OP_H
