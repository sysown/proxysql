#include "sql_engine/pgsql_remote_executor.h"
#include "sql_engine/datetime_parse.h"
#include <cstdlib>
#include <cstring>
#include <stdexcept>

// PostgreSQL OID constants (from server/catalog/pg_type_d.h)
#ifndef BOOLOID
#define BOOLOID         16
#define INT2OID         21
#define INT4OID         23
#define INT8OID         20
#define FLOAT4OID       700
#define FLOAT8OID       701
#define NUMERICOID      1700
#define TEXTOID         25
#define VARCHAROID      1043
#define BPCHAROID       1042
#define BYTEAOID        17
#define DATEOID         1082
#define TIMEOID         1083
#define TIMESTAMPOID    1114
#define TIMESTAMPTZOID  1184
#define JSONOID         114
#define JSONBOID        3802
#define NAMEOID         19
#define OIDOID          26
#endif

namespace sql_engine {

PgSQLRemoteExecutor::PgSQLRemoteExecutor() {}

PgSQLRemoteExecutor::~PgSQLRemoteExecutor() {
    disconnect_all();
}

void PgSQLRemoteExecutor::add_backend(const BackendConfig& config) {
    Connection c;
    c.config = config;
    c.conn = nullptr;
    c.connected = false;
    backends_[config.name] = std::move(c);
}

PgSQLRemoteExecutor::Connection& PgSQLRemoteExecutor::get_or_connect(const std::string& name) {
    auto it = backends_.find(name);
    if (it == backends_.end()) {
        throw std::runtime_error("PostgreSQL backend not found: " + name);
    }
    Connection& c = it->second;
    if (c.connected && c.conn) {
        if (PQstatus(c.conn) != CONNECTION_OK) {
            PQreset(c.conn);
            if (PQstatus(c.conn) != CONNECTION_OK) {
                PQfinish(c.conn);
                c.conn = nullptr;
                c.connected = false;
            }
        }
    }
    if (!c.connected || !c.conn) {
        // Per-session statement_timeout protects the 2PC coordinator from
        // hanging forever during PREPARE TRANSACTION / COMMIT PREPARED on a
        // wedged backend. 30s matches the MySQL side; override at compile
        // time if needed.
#ifndef SQL_ENGINE_PG_STATEMENT_TIMEOUT_MS
#define SQL_ENGINE_PG_STATEMENT_TIMEOUT_MS 30000
#endif
        std::string conninfo = "host=" + c.config.host
            + " port=" + std::to_string(c.config.port)
            + " user=" + c.config.user
            + " password=" + c.config.password
            + " dbname=" + c.config.database
            + " connect_timeout=5"
            + " options='-c statement_timeout="
                + std::to_string(SQL_ENGINE_PG_STATEMENT_TIMEOUT_MS) + "'";

        // SSL/TLS options
        if (!c.config.ssl_mode.empty())
            conninfo += " sslmode=" + c.config.ssl_mode;
        if (!c.config.ssl_ca.empty())
            conninfo += " sslrootcert=" + c.config.ssl_ca;
        if (!c.config.ssl_cert.empty())
            conninfo += " sslcert=" + c.config.ssl_cert;
        if (!c.config.ssl_key.empty())
            conninfo += " sslkey=" + c.config.ssl_key;

        c.conn = PQconnectdb(conninfo.c_str());
        if (PQstatus(c.conn) != CONNECTION_OK) {
            std::string err = PQerrorMessage(c.conn);
            PQfinish(c.conn);
            c.conn = nullptr;
            throw std::runtime_error("PostgreSQL connect failed for " + name + ": " + err);
        }
        c.connected = true;
    }
    return c;
}

ResultSet PgSQLRemoteExecutor::execute(const char* backend_name, sql_parser::StringRef sql) {
    ResultSet rs;
    try {
        Connection& c = get_or_connect(backend_name);
        std::string query(sql.ptr, sql.len);
        PGresult* res = PQexec(c.conn, query.c_str());
        if (!res) return rs;

        ExecStatusType status = PQresultStatus(res);
        if (status != PGRES_TUPLES_OK) {
            PQclear(res);
            return rs;
        }
        rs = pg_result_to_resultset(res);
        PQclear(res);
    } catch (const std::exception&) {
        // Connection error — return empty result
    }
    return rs;
}

DmlResult PgSQLRemoteExecutor::execute_dml(const char* backend_name, sql_parser::StringRef sql) {
    DmlResult result;
    try {
        Connection& c = get_or_connect(backend_name);
        std::string query(sql.ptr, sql.len);
        PGresult* res = PQexec(c.conn, query.c_str());
        if (!res) {
            result.error_message = "PQexec returned null";
            return result;
        }

        ExecStatusType status = PQresultStatus(res);
        if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK) {
            result.error_message = PQresultErrorMessage(res);
            PQclear(res);
            return result;
        }

        const char* cmd_tuples = PQcmdTuples(res);
        if (cmd_tuples && cmd_tuples[0]) {
            result.affected_rows = static_cast<uint64_t>(std::strtoull(cmd_tuples, nullptr, 10));
        }
        result.success = true;
        PQclear(res);
    } catch (const std::exception& e) {
        result.error_message = e.what();
    }
    return result;
}

void PgSQLRemoteExecutor::disconnect_all() {
    for (auto& pair : backends_) {
        if (pair.second.conn) {
            PQfinish(pair.second.conn);
            pair.second.conn = nullptr;
            pair.second.connected = false;
        }
    }
}

ResultSet PgSQLRemoteExecutor::pg_result_to_resultset(PGresult* res) {
    ResultSet rs;
    int num_fields = PQnfields(res);
    int num_rows = PQntuples(res);
    rs.column_count = static_cast<uint16_t>(num_fields);

    for (int i = 0; i < num_fields; ++i) {
        rs.column_names.emplace_back(PQfname(res, i));
    }

    for (int r = 0; r < num_rows; ++r) {
        Row& row = rs.add_heap_row(rs.column_count);
        for (int c = 0; c < num_fields; ++c) {
            bool is_null = PQgetisnull(res, r, c);
            Oid oid = PQftype(res, c);
            const char* data = PQgetvalue(res, r, c);
            int length = PQgetlength(res, r, c);
            Value v = pg_field_to_value(rs, data, length, oid, is_null);
            row.set(static_cast<uint16_t>(c), v);
        }
    }
    return rs;
}

Value PgSQLRemoteExecutor::pg_field_to_value(
    ResultSet& rs, const char* data, int length, Oid type, bool is_null) {

    if (is_null) return value_null();

    switch (type) {
        case BOOLOID:
            return value_bool(data[0] == 't' || data[0] == 'T');

        case INT2OID:
        case INT4OID:
        case INT8OID:
        case OIDOID:
            return value_int(std::strtoll(data, nullptr, 10));

        case FLOAT4OID:
        case FLOAT8OID:
            return value_double(std::strtod(data, nullptr));

        case NUMERICOID: {
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_string(s);
        }

        case DATEOID: {
            int32_t days = datetime_parse::parse_date(data);
            return value_date(days);
        }

        case TIMESTAMPOID: {
            int64_t us = datetime_parse::parse_datetime(data);
            return value_datetime(us);
        }

        case TIMESTAMPTZOID: {
            // PostgreSQL returns "YYYY-MM-DD HH:MM:SS+TZ". Parse and normalize to UTC.
            int64_t us = datetime_parse::parse_datetime_tz(data);
            return value_timestamp(us);
        }

        case TIMEOID: {
            int64_t us = datetime_parse::parse_time(data);
            return value_time(us);
        }

        case BYTEAOID: {
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_bytes(s);
        }

        case JSONOID:
        case JSONBOID: {
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_json(s);
        }

        default: {
            // TEXT, VARCHAR, BPCHAR, NAME, and everything else -- treat as string
            sql_parser::StringRef s = rs.own_string(data, static_cast<uint32_t>(length));
            return value_string(s);
        }
    }
}

} // namespace sql_engine
