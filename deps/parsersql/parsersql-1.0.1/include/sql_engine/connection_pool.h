#ifndef SQL_ENGINE_CONNECTION_POOL_H
#define SQL_ENGINE_CONNECTION_POOL_H

// Thread-safe connection pool for MySQL backends.
//
// Each backend name maps to a stack of idle MYSQL* handles with its own mutex.
// Threads check out a handle (creating one on demand), use it, and check it
// back in. Per-backend locking means concurrent queries to different backends
// never contend on the same mutex.

#include "sql_engine/backend_config.h"
#include <mysql/mysql.h>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <stdexcept>
#include <memory>

namespace sql_engine {

// Default timeouts (seconds). These bound how long any single libmysqlclient
// read or write can block. Without them, a wedged backend or a network
// partition during XA PREPARE would hang the entire 2PC coordinator
// indefinitely. Set generously enough that healthy OLTP queries never hit
// them (30s is well above normal p99 latency on any remotely sane backend).
//
// These are set at mysql_options time, so they apply to the current
// connection only; a different pooled connection on the same backend gets
// the same default.
#ifndef SQL_ENGINE_MYSQL_CONNECT_TIMEOUT_SEC
#define SQL_ENGINE_MYSQL_CONNECT_TIMEOUT_SEC 5
#endif
#ifndef SQL_ENGINE_MYSQL_READ_TIMEOUT_SEC
#define SQL_ENGINE_MYSQL_READ_TIMEOUT_SEC 30
#endif
#ifndef SQL_ENGINE_MYSQL_WRITE_TIMEOUT_SEC
#define SQL_ENGINE_MYSQL_WRITE_TIMEOUT_SEC 30
#endif

class ConnectionPool {
public:
    ConnectionPool() = default;

    ~ConnectionPool() {
        for (auto& kv : backends_) {
            auto& be = *kv.second;
            std::lock_guard<std::mutex> lk(be.mu);
            for (MYSQL* c : be.idle) {
                if (c) mysql_close(c);
            }
        }
    }

    // Register a backend. Must be called before any checkout for that name.
    void add_backend(const BackendConfig& config) {
        auto be = std::make_unique<Backend>();
        be->config = config;
        backends_[config.name] = std::move(be);
    }

    // Obtain a connection for the named backend.
    MYSQL* checkout(const std::string& backend) {
        Backend& be = get_backend(backend);
        {
            std::lock_guard<std::mutex> lk(be.mu);
            if (!be.idle.empty()) {
                MYSQL* c = be.idle.back();
                be.idle.pop_back();
                return c;
            }
        }
        // Create connection outside the lock (mysql_real_connect blocks)
        return create_connection(be);
    }

    // Return a connection to the pool for reuse.
    void checkin(const std::string& backend, MYSQL* conn) {
        if (!conn) return;
        Backend& be = get_backend(backend);
        std::lock_guard<std::mutex> lk(be.mu);
        be.idle.push_back(conn);
    }

private:
    struct Backend {
        BackendConfig config;
        std::mutex mu;
        std::vector<MYSQL*> idle;
    };

    std::unordered_map<std::string, std::unique_ptr<Backend>> backends_;

    Backend& get_backend(const std::string& name) {
        auto it = backends_.find(name);
        if (it == backends_.end()) {
            throw std::runtime_error("ConnectionPool: unknown backend: " + name);
        }
        return *it->second;
    }

    // Must NOT be called with be.mu held (mysql_real_connect blocks).
    static MYSQL* create_connection(Backend& be) {
        const BackendConfig& cfg = be.config;
        MYSQL* c = mysql_init(nullptr);
        if (!c) throw std::runtime_error("mysql_init failed for " + cfg.name);

        unsigned int connect_timeout = SQL_ENGINE_MYSQL_CONNECT_TIMEOUT_SEC;
        unsigned int read_timeout    = SQL_ENGINE_MYSQL_READ_TIMEOUT_SEC;
        unsigned int write_timeout   = SQL_ENGINE_MYSQL_WRITE_TIMEOUT_SEC;
        mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
        mysql_options(c, MYSQL_OPT_READ_TIMEOUT,    &read_timeout);
        mysql_options(c, MYSQL_OPT_WRITE_TIMEOUT,   &write_timeout);

        // SSL/TLS options
        if (!cfg.ssl_mode.empty()) {
            unsigned int ssl_mode_val = SSL_MODE_DISABLED;
            if (cfg.ssl_mode == "REQUIRED")        ssl_mode_val = SSL_MODE_REQUIRED;
            else if (cfg.ssl_mode == "VERIFY_CA")  ssl_mode_val = SSL_MODE_VERIFY_CA;
            else if (cfg.ssl_mode == "VERIFY_IDENTITY") ssl_mode_val = SSL_MODE_VERIFY_IDENTITY;
            mysql_options(c, MYSQL_OPT_SSL_MODE, &ssl_mode_val);
        }
        if (!cfg.ssl_ca.empty())
            mysql_options(c, MYSQL_OPT_SSL_CA, cfg.ssl_ca.c_str());
        if (!cfg.ssl_cert.empty())
            mysql_options(c, MYSQL_OPT_SSL_CERT, cfg.ssl_cert.c_str());
        if (!cfg.ssl_key.empty())
            mysql_options(c, MYSQL_OPT_SSL_KEY, cfg.ssl_key.c_str());

        if (!mysql_real_connect(c, cfg.host.c_str(), cfg.user.c_str(),
                                cfg.password.c_str(), cfg.database.c_str(),
                                cfg.port, nullptr, 0)) {
            std::string err = mysql_error(c);
            mysql_close(c);
            throw std::runtime_error("ConnectionPool connect failed for " + cfg.name + ": " + err);
        }
        mysql_set_character_set(c, "utf8mb4");
        return c;
    }
};

} // namespace sql_engine

#endif // SQL_ENGINE_CONNECTION_POOL_H
