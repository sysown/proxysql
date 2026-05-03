#ifndef SQL_ENGINE_BACKEND_CONFIG_H
#define SQL_ENGINE_BACKEND_CONFIG_H

#include "sql_parser/common.h"
#include <cstdint>
#include <string>

namespace sql_engine {

struct BackendConfig {
    std::string name;       // logical name: "shard_1", "analytics_db"
    std::string host;
    uint16_t port = 0;
    std::string user;
    std::string password;
    std::string database;
    sql_parser::Dialect dialect = sql_parser::Dialect::MySQL;

    // SSL/TLS configuration. Empty string = not configured (no SSL).
    // MySQL ssl_mode values: DISABLED, REQUIRED, VERIFY_CA, VERIFY_IDENTITY
    // PgSQL sslmode values: disable, require, verify-ca, verify-full
    std::string ssl_mode;
    std::string ssl_ca;
    std::string ssl_cert;
    std::string ssl_key;
};

} // namespace sql_engine

#endif // SQL_ENGINE_BACKEND_CONFIG_H
