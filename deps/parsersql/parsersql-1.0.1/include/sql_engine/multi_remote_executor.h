#ifndef SQL_ENGINE_MULTI_REMOTE_EXECUTOR_H
#define SQL_ENGINE_MULTI_REMOTE_EXECUTOR_H

#include "sql_engine/remote_executor.h"
#include "sql_engine/mysql_remote_executor.h"
#include "sql_engine/pgsql_remote_executor.h"
#include "sql_engine/backend_config.h"
#include "sql_parser/common.h"

#include <unordered_map>
#include <string>

namespace sql_engine {

class MultiRemoteExecutor : public RemoteExecutor {
public:
    MultiRemoteExecutor();
    ~MultiRemoteExecutor() override;

    void add_backend(const BackendConfig& config);
    ResultSet execute(const char* backend_name, sql_parser::StringRef sql) override;
    DmlResult execute_dml(const char* backend_name, sql_parser::StringRef sql) override;
    bool allows_unpinned_distributed_2pc() const override;
    void disconnect_all();

private:
    MySQLRemoteExecutor mysql_exec_;
    PgSQLRemoteExecutor pgsql_exec_;
    std::unordered_map<std::string, sql_parser::Dialect> backend_dialects_;
};

} // namespace sql_engine

#endif // SQL_ENGINE_MULTI_REMOTE_EXECUTOR_H
