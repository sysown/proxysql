#include "sql_engine/mysql_remote_executor.h"
#include "sql_engine/datetime_parse.h"
#include <cstdlib>
#include <cstring>
#include <stdexcept>

// Matches the defaults in connection_pool.h -- keeping them aligned so
// both connection paths behave identically. Override at compile time if
// your workload legitimately needs longer queries.
#ifndef SQL_ENGINE_MYSQL_CONNECT_TIMEOUT_SEC
#define SQL_ENGINE_MYSQL_CONNECT_TIMEOUT_SEC 5
#endif
#ifndef SQL_ENGINE_MYSQL_READ_TIMEOUT_SEC
#define SQL_ENGINE_MYSQL_READ_TIMEOUT_SEC 30
#endif
#ifndef SQL_ENGINE_MYSQL_WRITE_TIMEOUT_SEC
#define SQL_ENGINE_MYSQL_WRITE_TIMEOUT_SEC 30
#endif

namespace sql_engine {

MySQLRemoteExecutor::MySQLRemoteExecutor() {}

MySQLRemoteExecutor::~MySQLRemoteExecutor() {
    disconnect_all();
}

void MySQLRemoteExecutor::add_backend(const BackendConfig& config) {
    Connection c;
    c.config = config;
    c.conn = nullptr;
    c.connected = false;
    backends_[config.name] = std::move(c);
}

MySQLRemoteExecutor::Connection& MySQLRemoteExecutor::get_or_connect(const std::string& name) {
    auto it = backends_.find(name);
    if (it == backends_.end()) {
        throw std::runtime_error("MySQL backend not found: " + name);
    }
    Connection& c = it->second;
    if (c.connected && c.conn) {
        // Check if connection is alive
        if (mysql_ping(c.conn) != 0) {
            // Connection lost, try reconnect
            mysql_close(c.conn);
            c.conn = nullptr;
            c.connected = false;
        }
    }
    if (!c.connected || !c.conn) {
        c.conn = mysql_init(nullptr);
        if (!c.conn) {
            throw std::runtime_error("mysql_init failed for " + name);
        }
        // Connect + read + write timeouts. The read/write timeouts are
        // what protect the 2PC coordinator from hanging forever during
        // XA PREPARE / XA COMMIT on a wedged backend.
        unsigned int connect_timeout = SQL_ENGINE_MYSQL_CONNECT_TIMEOUT_SEC;
        unsigned int read_timeout    = SQL_ENGINE_MYSQL_READ_TIMEOUT_SEC;
        unsigned int write_timeout   = SQL_ENGINE_MYSQL_WRITE_TIMEOUT_SEC;
        mysql_options(c.conn, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
        mysql_options(c.conn, MYSQL_OPT_READ_TIMEOUT,    &read_timeout);
        mysql_options(c.conn, MYSQL_OPT_WRITE_TIMEOUT,   &write_timeout);

        // SSL/TLS options
        if (!c.config.ssl_mode.empty()) {
            unsigned int ssl_mode_val = SSL_MODE_DISABLED;
            if (c.config.ssl_mode == "REQUIRED")        ssl_mode_val = SSL_MODE_REQUIRED;
            else if (c.config.ssl_mode == "VERIFY_CA")  ssl_mode_val = SSL_MODE_VERIFY_CA;
            else if (c.config.ssl_mode == "VERIFY_IDENTITY") ssl_mode_val = SSL_MODE_VERIFY_IDENTITY;
            mysql_options(c.conn, MYSQL_OPT_SSL_MODE, &ssl_mode_val);
        }
        if (!c.config.ssl_ca.empty())
            mysql_options(c.conn, MYSQL_OPT_SSL_CA, c.config.ssl_ca.c_str());
        if (!c.config.ssl_cert.empty())
            mysql_options(c.conn, MYSQL_OPT_SSL_CERT, c.config.ssl_cert.c_str());
        if (!c.config.ssl_key.empty())
            mysql_options(c.conn, MYSQL_OPT_SSL_KEY, c.config.ssl_key.c_str());

        if (!mysql_real_connect(c.conn,
                                c.config.host.c_str(),
                                c.config.user.c_str(),
                                c.config.password.c_str(),
                                c.config.database.c_str(),
                                c.config.port,
                                nullptr, 0)) {
            std::string err = mysql_error(c.conn);
            mysql_close(c.conn);
            c.conn = nullptr;
            throw std::runtime_error("MySQL connect failed for " + name + ": " + err);
        }
        // Set UTF-8 charset
        mysql_set_character_set(c.conn, "utf8mb4");
        c.connected = true;
    }
    return c;
}

ResultSet MySQLRemoteExecutor::execute(const char* backend_name, sql_parser::StringRef sql) {
    ResultSet rs;
    try {
        Connection& c = get_or_connect(backend_name);
        std::string query(sql.ptr, sql.len);
        if (mysql_real_query(c.conn, query.c_str(), static_cast<unsigned long>(query.size())) != 0) {
            // Return empty result with error info (no crash)
            return rs;
        }
        MYSQL_RES* res = mysql_store_result(c.conn);
        if (!res) {
            // Might be a non-SELECT statement or error
            return rs;
        }
        rs = mysql_result_to_resultset(res);
        mysql_free_result(res);
    } catch (const std::exception&) {
        // Connection error — return empty result
    }
    return rs;
}

DmlResult MySQLRemoteExecutor::execute_dml(const char* backend_name, sql_parser::StringRef sql) {
    DmlResult result;
    try {
        Connection& c = get_or_connect(backend_name);
        std::string query(sql.ptr, sql.len);
        if (mysql_real_query(c.conn, query.c_str(), static_cast<unsigned long>(query.size())) != 0) {
            result.error_message = mysql_error(c.conn);
            return result;
        }
        // For DML, consume any result set (e.g., from stored procedures)
        MYSQL_RES* res = mysql_store_result(c.conn);
        if (res) mysql_free_result(res);

        result.affected_rows = mysql_affected_rows(c.conn);
        result.last_insert_id = mysql_insert_id(c.conn);
        result.success = true;
    } catch (const std::exception& e) {
        result.error_message = e.what();
    }
    return result;
}

void MySQLRemoteExecutor::disconnect_all() {
    for (auto& pair : backends_) {
        if (pair.second.conn) {
            mysql_close(pair.second.conn);
            pair.second.conn = nullptr;
            pair.second.connected = false;
        }
    }
}

ResultSet MySQLRemoteExecutor::mysql_result_to_resultset(MYSQL_RES* res) {
    ResultSet rs;
    unsigned int num_fields = mysql_num_fields(res);
    rs.column_count = static_cast<uint16_t>(num_fields);

    MYSQL_FIELD* fields = mysql_fetch_fields(res);
    for (unsigned int i = 0; i < num_fields; ++i) {
        rs.column_names.emplace_back(fields[i].name);
    }

    MYSQL_ROW mysql_row;
    while ((mysql_row = mysql_fetch_row(res)) != nullptr) {
        unsigned long* lengths = mysql_fetch_lengths(res);
        Row& row = rs.add_heap_row(rs.column_count);
        for (unsigned int i = 0; i < num_fields; ++i) {
            bool is_null = (mysql_row[i] == nullptr);
            Value v = mysql_field_to_value(
                rs, mysql_row[i], is_null ? 0 : lengths[i],
                fields[i].type, is_null);
            row.set(static_cast<uint16_t>(i), v);
        }
    }
    return rs;
}

Value MySQLRemoteExecutor::mysql_field_to_value(
    ResultSet& rs, const char* data, unsigned long length,
    enum_field_types type, bool is_null) {

    if (is_null) return value_null();

    switch (type) {
        case MYSQL_TYPE_TINY:
        case MYSQL_TYPE_SHORT:
        case MYSQL_TYPE_LONG:
        case MYSQL_TYPE_LONGLONG:
        case MYSQL_TYPE_INT24:
        case MYSQL_TYPE_YEAR:
            return value_int(std::strtoll(data, nullptr, 10));

        case MYSQL_TYPE_FLOAT:
        case MYSQL_TYPE_DOUBLE:
            return value_double(std::strtod(data, nullptr));

        case MYSQL_TYPE_DECIMAL:
        case MYSQL_TYPE_NEWDECIMAL: {
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_decimal(s);
        }

        case MYSQL_TYPE_DATE: {
            int32_t days = datetime_parse::parse_date(data);
            return value_date(days);
        }

        case MYSQL_TYPE_DATETIME:
        case MYSQL_TYPE_DATETIME2: {
            int64_t us = datetime_parse::parse_datetime(data);
            return value_datetime(us);
        }

        case MYSQL_TYPE_TIMESTAMP:
        case MYSQL_TYPE_TIMESTAMP2: {
            int64_t us = datetime_parse::parse_datetime(data);
            return value_timestamp(us);
        }

        case MYSQL_TYPE_TIME:
        case MYSQL_TYPE_TIME2: {
            int64_t us = datetime_parse::parse_time(data);
            return value_time(us);
        }

        case MYSQL_TYPE_BLOB:
        case MYSQL_TYPE_TINY_BLOB:
        case MYSQL_TYPE_MEDIUM_BLOB:
        case MYSQL_TYPE_LONG_BLOB: {
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_bytes(s);
        }

        case MYSQL_TYPE_JSON: {
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_json(s);
        }

        default: {
            // STRING, VAR_STRING, ENUM, SET, etc. — treat as string
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_string(s);
        }
    }
}

} // namespace sql_engine
