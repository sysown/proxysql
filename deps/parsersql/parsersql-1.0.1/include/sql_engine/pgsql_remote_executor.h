#ifndef SQL_ENGINE_PGSQL_REMOTE_EXECUTOR_H
#define SQL_ENGINE_PGSQL_REMOTE_EXECUTOR_H

#include "sql_engine/remote_executor.h"
#include "sql_engine/backend_config.h"
#include "sql_engine/value.h"
#include "sql_engine/row.h"
#include "sql_engine/result_set.h"

#include <libpq-fe.h>
#include <unordered_map>
#include <string>

namespace sql_engine {

class PgSQLRemoteExecutor : public RemoteExecutor {
public:
    PgSQLRemoteExecutor();
    ~PgSQLRemoteExecutor() override;

    void add_backend(const BackendConfig& config);
    ResultSet execute(const char* backend_name, sql_parser::StringRef sql) override;
    DmlResult execute_dml(const char* backend_name, sql_parser::StringRef sql) override;
    bool allows_unpinned_distributed_2pc() const override { return true; }
    void disconnect_all();

private:
    struct Connection {
        BackendConfig config;
        PGconn* conn = nullptr;
        bool connected = false;
    };

    std::unordered_map<std::string, Connection> backends_;

    Connection& get_or_connect(const std::string& name);
    ResultSet pg_result_to_resultset(PGresult* res);
    Value pg_field_to_value(ResultSet& rs, const char* data, int length,
                            Oid type, bool is_null);
};

} // namespace sql_engine

#endif // SQL_ENGINE_PGSQL_REMOTE_EXECUTOR_H
