#ifndef SQL_ENGINE_OPERATORS_SCAN_OP_H
#define SQL_ENGINE_OPERATORS_SCAN_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/data_source.h"

namespace sql_engine {

class ScanOperator : public Operator {
public:
    explicit ScanOperator(DataSource* source)
        : source_(source) {}

    void open() override {
        source_->open();
    }

    bool next(Row& out) override {
        return source_->next(out);
    }

    void close() override {
        source_->close();
    }

private:
    DataSource* source_;
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_SCAN_OP_H
