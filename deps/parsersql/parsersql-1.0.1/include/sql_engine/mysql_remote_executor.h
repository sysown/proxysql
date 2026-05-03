#ifndef SQL_ENGINE_MYSQL_REMOTE_EXECUTOR_H
#define SQL_ENGINE_MYSQL_REMOTE_EXECUTOR_H

#include "sql_engine/remote_executor.h"
#include "sql_engine/backend_config.h"
#include "sql_engine/value.h"
#include "sql_engine/row.h"
#include "sql_engine/result_set.h"

#include <mysql/mysql.h>
#include <unordered_map>
#include <string>

namespace sql_engine {

class MySQLRemoteExecutor : public RemoteExecutor {
public:
    MySQLRemoteExecutor();
    ~MySQLRemoteExecutor() override;

    void add_backend(const BackendConfig& config);
    ResultSet execute(const char* backend_name, sql_parser::StringRef sql) override;
    DmlResult execute_dml(const char* backend_name, sql_parser::StringRef sql) override;
    bool allows_unpinned_distributed_2pc() const override { return true; }
    void disconnect_all();

private:
    struct Connection {
        BackendConfig config;
        MYSQL* conn = nullptr;
        bool connected = false;
    };

    std::unordered_map<std::string, Connection> backends_;

    Connection& get_or_connect(const std::string& name);
    ResultSet mysql_result_to_resultset(MYSQL_RES* res);
    Value mysql_field_to_value(ResultSet& rs, const char* data,
                               unsigned long length,
                               enum_field_types type, bool is_null);
};

} // namespace sql_engine

#endif // SQL_ENGINE_MYSQL_REMOTE_EXECUTOR_H
