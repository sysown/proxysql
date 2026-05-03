#ifndef SQL_ENGINE_OPERATORS_REMOTE_SCAN_OP_H
#define SQL_ENGINE_OPERATORS_REMOTE_SCAN_OP_H

#include "sql_engine/operator.h"
#include "sql_engine/remote_executor.h"
#include "sql_engine/result_set.h"
#include "sql_parser/common.h"

namespace sql_engine {

class RemoteScanOperator : public Operator {
public:
    RemoteScanOperator(RemoteExecutor* executor,
                       const char* backend_name,
                       sql_parser::StringRef remote_sql)
        : executor_(executor), backend_name_(backend_name), remote_sql_(remote_sql) {}

    void open() override {
        cursor_ = 0;
        if (executor_) {
            results_ = executor_->execute(backend_name_, remote_sql_);
        }
    }

    bool next(Row& out) override {
        if (cursor_ >= results_.rows.size()) return false;
        out = results_.rows[cursor_++];
        return true;
    }

    void close() override {
        cursor_ = 0;
    }

private:
    RemoteExecutor* executor_;
    const char* backend_name_;
    sql_parser::StringRef remote_sql_;
    ResultSet results_;
    size_t cursor_ = 0;
};

} // namespace sql_engine

#endif // SQL_ENGINE_OPERATORS_REMOTE_SCAN_OP_H
