#ifndef SQL_ENGINE_SINGLE_BACKEND_TXN_H
#define SQL_ENGINE_SINGLE_BACKEND_TXN_H

#include "sql_engine/transaction_manager.h"
#include "sql_engine/remote_executor.h"
#include "sql_parser/common.h"

#include <string>
#include <cstring>

namespace sql_engine {

// SingleBackendTransactionManager forwards BEGIN/COMMIT/ROLLBACK to a single
// backend via RemoteExecutor. Savepoints are also forwarded as SQL statements.
class SingleBackendTransactionManager : public TransactionManager {
public:
    SingleBackendTransactionManager(RemoteExecutor& executor,
                                     const char* backend_name)
        : executor_(executor), backend_(backend_name) {}

    bool begin() override {
        auto r = executor_.execute_dml(backend_.c_str(),
                     sql_parser::StringRef{"BEGIN", 5});
        if (r.success) in_txn_ = true;
        return r.success;
    }

    bool commit() override {
        auto r = executor_.execute_dml(backend_.c_str(),
                     sql_parser::StringRef{"COMMIT", 6});
        if (r.success) in_txn_ = false;
        return r.success;
    }

    bool rollback() override {
        auto r = executor_.execute_dml(backend_.c_str(),
                     sql_parser::StringRef{"ROLLBACK", 8});
        if (r.success) in_txn_ = false;
        return r.success;
    }

    bool savepoint(const char* name) override {
        if (!in_txn_) return false;
        std::string sql = "SAVEPOINT " + std::string(name);
        auto r = executor_.execute_dml(backend_.c_str(),
                     sql_parser::StringRef{sql.c_str(),
                         static_cast<uint32_t>(sql.size())});
        return r.success;
    }

    bool rollback_to(const char* name) override {
        if (!in_txn_) return false;
        std::string sql = "ROLLBACK TO SAVEPOINT " + std::string(name);
        auto r = executor_.execute_dml(backend_.c_str(),
                     sql_parser::StringRef{sql.c_str(),
                         static_cast<uint32_t>(sql.size())});
        return r.success;
    }

    bool release_savepoint(const char* name) override {
        if (!in_txn_) return false;
        std::string sql = "RELEASE SAVEPOINT " + std::string(name);
        auto r = executor_.execute_dml(backend_.c_str(),
                     sql_parser::StringRef{sql.c_str(),
                         static_cast<uint32_t>(sql.size())});
        return r.success;
    }

    bool in_transaction() const override { return in_txn_; }
    bool is_auto_commit() const override { return auto_commit_; }
    void set_auto_commit(bool ac) override { auto_commit_ = ac; }

    const std::string& backend_name() const { return backend_; }

private:
    RemoteExecutor& executor_;
    std::string backend_;
    bool in_txn_ = false;
    bool auto_commit_ = true;
};

} // namespace sql_engine

#endif // SQL_ENGINE_SINGLE_BACKEND_TXN_H
