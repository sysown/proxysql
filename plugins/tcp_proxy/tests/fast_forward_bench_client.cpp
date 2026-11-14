// Native MySQL/PostgreSQL benchmark client for the TCP-vs-fast-forward study.
//
// The runner only orchestrates.  Every measured connection, SQL statement,
// result comparison and steady_clock sample is performed here in native code.
// The same executable and the same SQL/result validation are used for direct,
// mapped-native-TCP and permanent SQL-fast-forward paths.
//
// Passwords are read from a caller-owned 0600 config file; they are never
// accepted on the command line.
//
// Build (see Makefile.fast-forward):
//   g++ -std=c++17 -O2 -pthread ... fast_forward_bench_client.cpp ...
//
// Modes:
//   verify       one connection/query/result verification
//   hold         verify, print a ready JSON line, keep the socket open on stdin
//   rtt          N native clients, barrier, warmups + timed 64B RTT samples
//   connections  N native clients, barrier, repeated connect/query/close cycles
//   throughput   N persistent native clients, barrier, timed payload queries

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <mysql.h>
#include <libpq-fe.h>

namespace {

using SteadyClock = std::chrono::steady_clock;

constexpr const char* kAlphabet =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
constexpr const char* kSelect1Sql = "SELECT 1";
constexpr const char* kSelect1Expected = "1";

struct Config {
    std::string protocol;
    std::string host;
    unsigned port = 0;
    std::string user;
    std::string password;
    std::string database;
};

struct Options {
    std::string config_path;
    std::string mode = "verify";
    std::string workload = "literal";
    std::size_t payload_bytes = 64;
    std::size_t warmups = 0;
    std::size_t samples = 0;
    unsigned clients = 1;
    double duration_seconds = 0.0;
    unsigned timeout_ms = 2000;
    unsigned hold_seconds = 30;
    bool corrupt_expectation = false;
    bool negative_timeout_test = false;
    bool negative_timeout_completes = false;
    bool versions = false;
    unsigned inject_late_error_ms = 0;
};

struct WorkloadSpec {
    std::string sql;
    std::string expected;
    bool select1 = false;
};

struct ClientError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Result {
    std::string payload;
    std::string local_port;
    bool tls_used = false;
    bool ssl_in_use = false;
    bool gssenc_in_use = false;
    int tcp_nodelay = -1;
    bool compression = false;
    std::string ssl_cipher;
    unsigned long handshake_server_id = 0;
};

struct ThreadOutcome {
    std::vector<std::uint64_t> samples_ns;
    std::vector<std::uint64_t> connect_latencies_ns;
    std::uint64_t queries = 0;
    std::uint64_t cycles = 0;
    std::uint64_t request_bytes = 0;
    std::uint64_t response_bytes = 0;
    std::uint64_t sql_text_bytes = 0;
    std::string local_port;
    std::string error;
    bool tls_used = false;
    bool ssl_in_use = false;
    bool gssenc_in_use = false;
    int tcp_nodelay = -1;
    bool compression = false;
    std::string ssl_cipher;
    unsigned long handshake_server_id = 0;
};

std::string trim(std::string value) {
    const char* whitespace = " \t\r\n";
    const std::size_t first = value.find_first_not_of(whitespace);
    if (first == std::string::npos) return {};
    const std::size_t last = value.find_last_not_of(whitespace);
    return value.substr(first, last - first + 1);
}

Config load_config(const std::string& path) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0) {
        throw ClientError("cannot stat config file: " + path);
    }
    if ((st.st_mode & 077) != 0) {
        throw ClientError("config file must not be readable by group/other: " + path);
    }
    std::ifstream in(path);
    if (!in) throw ClientError("cannot open config file: " + path);
    std::map<std::string, std::string> values;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) throw ClientError("invalid config line");
        values[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }
    Config c;
    c.protocol = values["protocol"];
    c.host = values["host"];
    c.user = values["user"];
    c.password = values["password"];
    c.database = values["database"];
    if (c.protocol != "mysql" && c.protocol != "pgsql") {
        throw ClientError("config protocol must be mysql or pgsql");
    }
    if (c.host.empty() || c.user.empty() || values["port"].empty()) {
        throw ClientError("config requires protocol, host, port, user and password");
    }
    char* end = nullptr;
    const unsigned long port = std::strtoul(values["port"].c_str(), &end, 10);
    if (!end || *end != '\0' || port == 0 || port > 65535) {
        throw ClientError("invalid config port");
    }
    c.port = static_cast<unsigned>(port);
    return c;
}

std::string payload_for(std::size_t size) {
    std::string payload;
    payload.resize(size);
    for (std::size_t i = 0; i < size; ++i) payload[i] = kAlphabet[i % 62];
    return payload;
}

std::uint64_t fnv1a64(const std::string& value) {
    std::uint64_t hash = 1469598103934665603ULL;
    for (unsigned char c : value) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::string hex64(std::uint64_t value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%016llx",
                  static_cast<unsigned long long>(value));
    return buffer;
}

std::string json_escape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buffer[7];
                    std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                    out += buffer;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string quote(const std::string& value) {
    return "\"" + json_escape(value) + "\"";
}

std::string build_sql(const std::string& payload) {
    return "SELECT '" + payload + "' AS ff_benchmark_payload";
}

WorkloadSpec build_workload(const Options& options) {
    if (options.workload == "select1") {
        return WorkloadSpec{kSelect1Sql, kSelect1Expected, true};
    }
    return WorkloadSpec{"", payload_for(options.payload_bytes), false};
}

std::string workload_json(const WorkloadSpec& workload) {
    if (workload.select1) {
        return ",\"workload\":\"select1\",\"sql\":\"" +
               std::string(kSelect1Sql) + "\",\"expected_result\":\"" +
               std::string(kSelect1Expected) + "\"";
    }
    return ",\"workload\":\"literal\"";
}


std::uint64_t elapsed_ns(const SteadyClock::time_point& start,
                         const SteadyClock::time_point& end) {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

unsigned ceil_seconds(unsigned milliseconds) {
    if (milliseconds == 0) return 1;
    return static_cast<unsigned>((milliseconds + 999U) / 1000U);
}

std::string local_tcp_port(int fd) {
    sockaddr_storage addr {};
    socklen_t length = sizeof(addr);
    if (fd < 0 || getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &length) != 0) {
        return "";
    }
    if (addr.ss_family == AF_INET) {
        const auto* in = reinterpret_cast<const sockaddr_in*>(&addr);
        return std::to_string(ntohs(in->sin_port));
    }
    if (addr.ss_family == AF_INET6) {
        const auto* in6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        return std::to_string(ntohs(in6->sin6_port));
    }
    return "";
}

int enable_and_observe_tcp_nodelay(int fd) {
    if (fd < 0) return -1;
    const int enabled = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) {
        return -1;
    }
    int observed = 0;
    socklen_t length = sizeof(observed);
    if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &observed, &length) != 0) {
        return -1;
    }
    return observed;
}

std::string library_versions_json() {
    std::ostringstream out;
    out << "{\"mariadb_connector_c\":" << quote(mysql_get_client_info())
        << ",\"libpq\":" << quote(std::to_string(PQlibVersion())) << "}";
    return out.str();
}

struct MysqlThreadGuard {
    MysqlThreadGuard() { active_ = mysql_thread_init() == 0; }
    ~MysqlThreadGuard() {
        if (active_) mysql_thread_end();
    }
    MysqlThreadGuard(const MysqlThreadGuard&) = delete;
    MysqlThreadGuard& operator=(const MysqlThreadGuard&) = delete;
    bool active_ = false;
};

struct MysqlLibraryGuard {
    MysqlLibraryGuard() : active_(mysql_library_init(0, nullptr, nullptr) == 0) {}
    ~MysqlLibraryGuard() {
        if (active_) mysql_library_end();
    }
    MysqlLibraryGuard(const MysqlLibraryGuard&) = delete;
    MysqlLibraryGuard& operator=(const MysqlLibraryGuard&) = delete;
    bool active_ = false;
};

class Connection {
public:
    virtual ~Connection() = default;
    virtual Result query_verify(const std::string& payload, bool corrupt_expectation) = 0;
    virtual Result query_only(const std::string& sql, const std::string& expected,
                              bool corrupt_expectation) = 0;
    virtual std::string local_port() const = 0;
};

Result execute_workload(Connection& connection, const WorkloadSpec& workload,
                        bool corrupt_expectation = false) {
    if (workload.select1) {
        return connection.query_only(workload.sql, workload.expected,
                                     corrupt_expectation);
    }
    return connection.query_verify(workload.expected, corrupt_expectation);
}

class MysqlConnection final : public Connection {
public:
    MysqlConnection(const Config& config, unsigned timeout_ms) {
        mysql_ = mysql_init(nullptr);
        if (!mysql_) throw ClientError("mysql_init failed");
        bool reconnect = false;
        unsigned protocol = MYSQL_PROTOCOL_TCP;
        unsigned connect_timeout = ceil_seconds(timeout_ms);
        unsigned io_timeout = ceil_seconds(timeout_ms);
        bool ssl_enforce = false;
        unsigned long max_packet = 64UL * 1024UL * 1024UL;
        mysql_options(mysql_, MYSQL_OPT_RECONNECT, &reconnect);
        mysql_options(mysql_, MYSQL_OPT_PROTOCOL, &protocol);
        mysql_options(mysql_, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
        mysql_options(mysql_, MYSQL_OPT_READ_TIMEOUT, &io_timeout);
        mysql_options(mysql_, MYSQL_OPT_WRITE_TIMEOUT, &io_timeout);
        mysql_options(mysql_, MYSQL_OPT_SSL_ENFORCE, &ssl_enforce);
        mysql_options(mysql_, MYSQL_OPT_MAX_ALLOWED_PACKET, &max_packet);
        if (!mysql_real_connect(mysql_, config.host.c_str(), config.user.c_str(),
                                config.password.c_str(), config.database.c_str(),
                                config.port, nullptr, 0)) {
            const std::string error = mysql_error(mysql_);
            mysql_close(mysql_);
            mysql_ = nullptr;
            throw ClientError("mysql connect failed: " + error);
        }
        const char* cipher = mysql_get_ssl_cipher(mysql_);
        ssl_cipher_ = cipher ? cipher : "";
        tls_used_ = !ssl_cipher_.empty();
        compression_ = (mysql_->client_flag & CLIENT_COMPRESS) != 0;
        handshake_server_id_ = mysql_thread_id(mysql_);
        tcp_nodelay_ = enable_and_observe_tcp_nodelay(mysql_get_socket(mysql_));
        if (tls_used_) {
            throw ClientError("TLS unexpectedly negotiated for MySQL path");
        }
        if (compression_) {
            throw ClientError("CLIENT_COMPRESS unexpectedly negotiated");
        }
        if (tcp_nodelay_ != 1) {
            throw ClientError("TCP_NODELAY observation is not 1 for MySQL");
        }
    }

    ~MysqlConnection() override {
        if (mysql_) mysql_close(mysql_);
    }

    Result query_verify(const std::string& payload, bool corrupt_expectation) override {
        const std::string sql = build_sql(payload);
        return execute(sql, payload, corrupt_expectation);
    }

    Result query_only(const std::string& sql, const std::string& expected,
                      bool corrupt_expectation) override {
        return execute(sql, expected, corrupt_expectation);
    }

    std::string local_port() const override {
        return local_tcp_port(mysql_get_socket(mysql_));
    }

private:
    Result execute(const std::string& sql, const std::string& expected,
                   bool corrupt_expectation) {
        if (mysql_real_query(mysql_, sql.data(), sql.size()) != 0) {
            throw ClientError("mysql query failed: " + std::string(mysql_error(mysql_)));
        }
        MYSQL_RES* result = mysql_store_result(mysql_);
        if (!result) {
            throw ClientError("mysql_store_result failed: " + std::string(mysql_error(mysql_)));
        }
        if (mysql_num_rows(result) != 1) {
            const auto rows = static_cast<unsigned long long>(mysql_num_rows(result));
            mysql_free_result(result);
            throw ClientError("mysql query returned " + std::to_string(rows) +
                              " rows, expected exactly 1");
        }
        MYSQL_ROW row = mysql_fetch_row(result);
        unsigned long* lengths = mysql_fetch_lengths(result);
        if (!row || !lengths) {
            mysql_free_result(result);
            throw ClientError("mysql query returned no row");
        }
        if (mysql_num_fields(result) != 1) {
            mysql_free_result(result);
            throw ClientError("mysql query returned unexpected field count");
        }
        std::string actual(row[0], lengths[0]);
        mysql_free_result(result);
        std::string wanted = expected;
        if (corrupt_expectation && !wanted.empty()) {
            wanted[wanted.size() / 2] = (wanted[wanted.size() / 2] == 'x') ? 'y' : 'x';
        }
        if (actual.size() != wanted.size() || actual != wanted) {
            throw ClientError("payload mismatch: got " + std::to_string(actual.size()) +
                              " bytes expected " + std::to_string(wanted.size()));
        }
        Result result_value;
        result_value.local_port = local_port();
        result_value.tls_used = tls_used_;
        result_value.ssl_in_use = tls_used_;
        result_value.gssenc_in_use = false;
        result_value.tcp_nodelay = tcp_nodelay_;
        result_value.compression = compression_;
        result_value.ssl_cipher = ssl_cipher_;
        result_value.handshake_server_id = handshake_server_id_;
        return result_value;
    }

    MYSQL* mysql_ = nullptr;
    bool tls_used_ = false;
    bool compression_ = false;
    int tcp_nodelay_ = -1;
    std::string ssl_cipher_;
    unsigned long handshake_server_id_ = 0;
};

class PgConnection final : public Connection {
public:
    PgConnection(const Config& config, unsigned timeout_ms) : timeout_ms_(timeout_ms) {
        const std::string port = std::to_string(config.port);
        const std::string timeout = std::to_string(ceil_seconds(timeout_ms));
        const char* keys[] = {"host", "port", "user", "password", "dbname",
                              "sslmode", "gssencmode", "connect_timeout",
                              "application_name", nullptr};
        const char* values[] = {config.host.c_str(), port.c_str(), config.user.c_str(),
                                config.password.c_str(), config.database.c_str(),
                                "disable", "disable", timeout.c_str(), "ff-benchmark",
                                nullptr};
        conn_ = PQconnectStartParams(keys, values, 0);
        if (!conn_) throw ClientError("PQconnectStartParams failed");
        const auto deadline = SteadyClock::now() +
                              std::chrono::milliseconds(timeout_ms);
        PostgresPollingStatusType status = PGRES_POLLING_WRITING;
        while (status != PGRES_POLLING_OK) {
            if (status == PGRES_POLLING_FAILED) {
                throw ClientError("pgsql connect failed: " + error_message());
            }
            const int fd = PQsocket(conn_);
            if (fd < 0) throw ClientError("pgsql connect lost socket");
            short events = (status == PGRES_POLLING_READING) ? POLLIN : POLLOUT;
            const int wait_ms = remaining_ms(deadline);
            if (wait_ms <= 0) throw ClientError("pgsql connect timeout");
            pollfd pfd {fd, events, 0};
            const int rc = poll(&pfd, 1, wait_ms);
            if (rc < 0) {
                if (errno == EINTR) continue;
                throw ClientError("pgsql connect poll failed");
            }
            if (rc == 0) throw ClientError("pgsql connect timeout");
            status = PQconnectPoll(conn_);
        }
        if (PQstatus(conn_) != CONNECTION_OK) {
            throw ClientError("pgsql connection not OK: " + error_message());
        }
        if (PQsslInUse(conn_)) {
            PQfinish(conn_);
            conn_ = nullptr;
            throw ClientError("TLS unexpectedly negotiated for PostgreSQL path");
        }
        if (PQgssEncInUse(conn_)) {
            PQfinish(conn_);
            conn_ = nullptr;
            throw ClientError("GSS encryption unexpectedly negotiated for PostgreSQL path");
        }
        tcp_nodelay_ = enable_and_observe_tcp_nodelay(PQsocket(conn_));
        if (tcp_nodelay_ != 1) {
            PQfinish(conn_);
            conn_ = nullptr;
            throw ClientError("TCP_NODELAY observation is not 1 for PostgreSQL");
        }
        if (PQsetnonblocking(conn_, 1) != 0) {
            throw ClientError("PQsetnonblocking failed: " + error_message());
        }
        handshake_server_id_ = static_cast<unsigned long>(PQbackendPID(conn_));
    }

    ~PgConnection() override {
        if (conn_) PQfinish(conn_);
    }

    Result query_verify(const std::string& payload, bool corrupt_expectation) override {
        return execute(build_sql(payload), payload, corrupt_expectation);
    }

    Result query_only(const std::string& sql, const std::string& expected,
                      bool corrupt_expectation) override {
        return execute(sql, expected, corrupt_expectation);
    }

    std::string local_port() const override { return local_tcp_port(PQsocket(conn_)); }

private:
    int remaining_ms(const SteadyClock::time_point& deadline) const {
        const auto now = SteadyClock::now();
        if (now >= deadline) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    }

    std::string error_message() const {
        const char* message = conn_ ? PQerrorMessage(conn_) : "no connection";
        return message ? message : "unknown libpq error";
    }

    Result execute(const std::string& sql, const std::string& expected,
                   bool corrupt_expectation) {
        if (!PQsendQuery(conn_, sql.c_str())) {
            throw ClientError("PQsendQuery failed: " + error_message());
        }
        const auto deadline = SteadyClock::now() +
                              std::chrono::milliseconds(timeout_ms_);
        while (true) {
            const int flush = PQflush(conn_);
            if (flush < 0) throw ClientError("PQflush failed: " + error_message());
            if (flush > 0) {
                const int wait_ms = remaining_ms(deadline);
                if (wait_ms <= 0) throw ClientError("pgsql query write timeout");
                pollfd pfd {PQsocket(conn_), POLLOUT, 0};
                const int rc = poll(&pfd, 1, wait_ms);
                if (rc < 0 && errno == EINTR) continue;
                if (rc <= 0) throw ClientError("pgsql query write timeout");
                continue;
            }
            if (!PQisBusy(conn_)) break;
            const int wait_ms = remaining_ms(deadline);
            if (wait_ms <= 0) throw ClientError("pgsql query read timeout");
            pollfd pfd {PQsocket(conn_), POLLIN, 0};
            const int rc = poll(&pfd, 1, wait_ms);
            if (rc < 0) {
                if (errno == EINTR) continue;
                throw ClientError("pgsql query poll failed");
            }
            if (rc == 0) throw ClientError("pgsql query read timeout");
            if (!PQconsumeInput(conn_)) {
                throw ClientError("PQconsumeInput failed: " + error_message());
            }
        }

        PGresult* final = nullptr;
        PGresult* item = nullptr;
        while ((item = PQgetResult(conn_)) != nullptr) {
            if (final) PQclear(final);
            final = item;
            if (PQresultStatus(final) == PGRES_FATAL_ERROR) {
                const std::string error = PQresultErrorMessage(final);
                PQclear(final);
                throw ClientError("pgsql query failed: " + error);
            }
        }
        if (!final) throw ClientError("pgsql query returned no result");
        const ExecStatusType status = PQresultStatus(final);
        if (status != PGRES_TUPLES_OK) {
            PQclear(final);
            throw ClientError("pgsql query returned unexpected result status");
        }
        if (PQntuples(final) != 1 || PQnfields(final) != 1) {
            PQclear(final);
            throw ClientError("pgsql query returned unexpected row/field count");
        }
        const int length = PQgetlength(final, 0, 0);
        const char* value = PQgetvalue(final, 0, 0);
        std::string actual(value ? value : "", length > 0 ? static_cast<std::size_t>(length) : 0);
        PQclear(final);
        std::string wanted = expected;
        if (corrupt_expectation && !wanted.empty()) {
            wanted[wanted.size() / 2] = (wanted[wanted.size() / 2] == 'x') ? 'y' : 'x';
        }
        if (actual.size() != wanted.size() || actual != wanted) {
            throw ClientError("payload mismatch: got " + std::to_string(actual.size()) +
                              " bytes expected " + std::to_string(wanted.size()));
        }
        Result result_value;
        result_value.local_port = local_port();
        result_value.tls_used = false;
        result_value.ssl_in_use = false;
        result_value.gssenc_in_use = false;
        result_value.tcp_nodelay = tcp_nodelay_;
        result_value.compression = false;
        result_value.ssl_cipher = "";
        result_value.handshake_server_id = handshake_server_id_;
        return result_value;
    }

    PGconn* conn_ = nullptr;
    unsigned timeout_ms_ = 2000;
    int tcp_nodelay_ = -1;
    unsigned long handshake_server_id_ = 0;
};

std::unique_ptr<Connection> connect_client(const Config& config, unsigned timeout_ms) {
    if (config.protocol == "mysql") {
        return std::make_unique<MysqlConnection>(config, timeout_ms);
    }
    return std::make_unique<PgConnection>(config, timeout_ms);
}

struct StartGate {
    explicit StartGate(unsigned clients) {
        if (pthread_barrier_init(&barrier, nullptr, clients + 1) != 0) {
            throw ClientError("pthread_barrier_init failed");
        }
    }
    ~StartGate() { pthread_barrier_destroy(&barrier); }
    void arrive_and_wait() {
        const int rc = pthread_barrier_wait(&barrier);
        if (rc != 0 && rc != PTHREAD_BARRIER_SERIAL_THREAD) {
            throw ClientError("pthread_barrier_wait failed");
        }
    }
    pthread_barrier_t barrier {};
};

void emit_connection(const Result& result, const WorkloadSpec& workload,
                     std::uint64_t elapsed) {
    std::cout << "{\"ok\":true,\"mode\":\"verify\",\"local_port\":"
              << quote(result.local_port) << ",\"tls_used\":"
              << (result.tls_used ? "true" : "false") << ",\"ssl_in_use\":"
              << (result.ssl_in_use ? "true" : "false") << ",\"gssenc_in_use\":"
              << (result.gssenc_in_use ? "true" : "false")
              << ",\"tcp_nodelay\":" << result.tcp_nodelay
              << ",\"ssl_cipher\":" << quote(result.ssl_cipher)
              << ",\"compression\":" << (result.compression ? "true" : "false")
              << ",\"handshake_server_id\":" << result.handshake_server_id
              << ",\"payload_bytes\":" << workload.expected.size()
              << ",\"payload_fnv1a64\":" << quote(hex64(fnv1a64(workload.expected)))
              << workload_json(workload)
              << ",\"library_versions\":" << library_versions_json()
              << ",\"elapsed_ns\":" << elapsed << "}" << std::endl;
}

void emit_ready(const Result& result, const WorkloadSpec& workload,
                unsigned hold_seconds) {
    std::cout << "{\"ok\":true,\"mode\":\"hold\",\"ready\":true,\"local_port\":"
              << quote(result.local_port) << ",\"tls_used\":"
              << (result.tls_used ? "true" : "false") << ",\"ssl_in_use\":"
              << (result.ssl_in_use ? "true" : "false") << ",\"gssenc_in_use\":"
              << (result.gssenc_in_use ? "true" : "false")
              << ",\"tcp_nodelay\":" << result.tcp_nodelay
              << ",\"ssl_cipher\":" << quote(result.ssl_cipher)
              << ",\"compression\":" << (result.compression ? "true" : "false")
              << ",\"handshake_server_id\":" << result.handshake_server_id
              << ",\"payload_bytes\":" << workload.expected.size()
              << ",\"payload_fnv1a64\":" << quote(hex64(fnv1a64(workload.expected)))
              << workload_json(workload)
              << ",\"library_versions\":" << library_versions_json()
              << ",\"hold_seconds\":" << hold_seconds << "}" << std::endl;
}

std::uint64_t percentile(std::vector<std::uint64_t> values, double fraction) {
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const double pos = fraction * static_cast<double>(values.size() - 1);
    const std::size_t index = static_cast<std::size_t>(std::llround(pos));
    return values[std::min(index, values.size() - 1)];
}

std::string thread_errors(const std::vector<ThreadOutcome>& outcomes) {
    std::ostringstream out;
    bool first = true;
    for (std::size_t i = 0; i < outcomes.size(); ++i) {
        if (!outcomes[i].error.empty()) {
            if (!first) out << "; ";
            first = false;
            out << "client " << i << ": " << outcomes[i].error;
        }
    }
    return out.str();
}

int run_rtt(const Config& config, const Options& options) {
    StartGate gate(options.clients);
    std::vector<ThreadOutcome> outcomes(options.clients);
    std::vector<std::thread> threads;
    const WorkloadSpec workload = build_workload(options);
    std::atomic<bool> failed {false};

    for (unsigned index = 0; index < options.clients; ++index) {
        threads.emplace_back([&, index]() {
            MysqlThreadGuard mysql_thread;
            ThreadOutcome& out = outcomes[index];
            bool arrived = false;
            try {
                auto connection = connect_client(config, options.timeout_ms);
                out.local_port = connection->local_port();
                for (std::size_t i = 0; i < options.warmups; ++i) {
                    const Result result = execute_workload(*connection, workload);
                    out.tls_used = result.tls_used;
                    out.ssl_in_use = result.ssl_in_use;
                    out.gssenc_in_use = result.gssenc_in_use;
                    out.tcp_nodelay = result.tcp_nodelay;
                    out.compression = result.compression;
                    out.ssl_cipher = result.ssl_cipher;
                    out.handshake_server_id = result.handshake_server_id;
                }
                gate.arrive_and_wait();
                arrived = true;
                out.samples_ns.reserve(options.samples);
                for (std::size_t i = 0; i < options.samples; ++i) {
                    const auto start = SteadyClock::now();
                    const Result result = execute_workload(*connection, workload);
                    const auto end = SteadyClock::now();
                    out.samples_ns.push_back(elapsed_ns(start, end));
                    out.tls_used = result.tls_used;
                    out.ssl_in_use = result.ssl_in_use;
                    out.gssenc_in_use = result.gssenc_in_use;
                    out.tcp_nodelay = result.tcp_nodelay;
                    out.compression = result.compression;
                    out.ssl_cipher = result.ssl_cipher;
                    out.handshake_server_id = result.handshake_server_id;
                }
            } catch (const std::exception& exc) {
                failed = true;
                out.error = exc.what();
                if (!arrived) gate.arrive_and_wait();
            }
        });
    }
    gate.arrive_and_wait();
    for (auto& thread : threads) thread.join();

    std::vector<std::uint64_t> all_samples;
    for (const auto& out : outcomes) {
        all_samples.insert(all_samples.end(), out.samples_ns.begin(), out.samples_ns.end());
    }
    std::ostringstream json;
    json << "{\"ok\":" << (!failed && all_samples.size() ==
                           options.samples * options.clients ? "true" : "false")
         << ",\"mode\":\"rtt\",\"protocol\":" << quote(config.protocol)
         << ",\"clients\":" << options.clients << ",\"warmups\":"
         << options.warmups << ",\"samples_per_client\":" << options.samples
         << ",\"payload_bytes\":" << workload.expected.size()
         << ",\"payload_fnv1a64\":" << quote(hex64(fnv1a64(workload.expected)))
         << workload_json(workload)
         << ",\"p50_ns\":" << percentile(all_samples, 0.50)
         << ",\"p95_ns\":" << percentile(all_samples, 0.95)
         << ",\"p99_ns\":" << percentile(all_samples, 0.99)
         << ",\"threads\":[";
    for (std::size_t i = 0; i < outcomes.size(); ++i) {
        if (i) json << ",";
        const auto& out = outcomes[i];
        json << "{\"index\":" << i << ",\"local_port\":" << quote(out.local_port)
             << ",\"samples\":" << out.samples_ns.size() << ",\"tls_used\":"
             << (out.tls_used ? "true" : "false")
             << ",\"ssl_in_use\":" << (out.ssl_in_use ? "true" : "false")
             << ",\"gssenc_in_use\":" << (out.gssenc_in_use ? "true" : "false")
             << ",\"tcp_nodelay\":" << out.tcp_nodelay
             << ",\"compression\":" << (out.compression ? "true" : "false")
             << ",\"ssl_cipher\":" << quote(out.ssl_cipher)
             << ",\"handshake_server_id\":" << out.handshake_server_id
             << ",\"error\":" << quote(out.error)
             << ",\"samples_ns\":[";
        for (std::size_t j = 0; j < out.samples_ns.size(); ++j) {
            if (j) json << ",";
            json << out.samples_ns[j];
        }
        json << "]}";
    }
    json << "]";
    bool tls_used = false, ssl_in_use = false, gssenc_in_use = false, compression = false;
    int tcp_nodelay = -1;
    std::string ssl_cipher;
    for (const auto& out : outcomes) {
        tls_used = tls_used || out.tls_used;
        ssl_in_use = ssl_in_use || out.ssl_in_use;
        gssenc_in_use = gssenc_in_use || out.gssenc_in_use;
        compression = compression || out.compression;
        if (tcp_nodelay == -1) tcp_nodelay = out.tcp_nodelay;
        if (ssl_cipher.empty()) ssl_cipher = out.ssl_cipher;
    }
    json << ",\"tls_used\":" << (tls_used ? "true" : "false")
         << ",\"ssl_in_use\":" << (ssl_in_use ? "true" : "false")
         << ",\"gssenc_in_use\":" << (gssenc_in_use ? "true" : "false")
         << ",\"tcp_nodelay\":" << tcp_nodelay
         << ",\"compression\":" << (compression ? "true" : "false")
         << ",\"ssl_cipher\":" << quote(ssl_cipher)
         << ",\"library_versions\":" << library_versions_json();
    const std::string errors = thread_errors(outcomes);
    if (!errors.empty()) json << ",\"error\":" << quote(errors);
    json << "}";
    std::cout << json.str() << std::endl;
    return (failed || all_samples.size() != options.samples * options.clients) ? 1 : 0;
}

int run_connections(const Config& config, const Options& options) {
    StartGate gate(options.clients);
    std::vector<ThreadOutcome> outcomes(options.clients);
    std::vector<std::thread> threads;
    const WorkloadSpec workload = build_workload(options);
    std::atomic<bool> failed {false};
    std::atomic<bool> stop {false};
    std::atomic<bool> phase_started {false};
    std::atomic<std::int64_t> phase_start_ns {0};
    std::atomic<std::int64_t> phase_deadline_ns {0};

    for (unsigned index = 0; index < options.clients; ++index) {
        threads.emplace_back([&, index]() {
            MysqlThreadGuard mysql_thread;
            ThreadOutcome& out = outcomes[index];
            try {
                gate.arrive_and_wait();
                while (!phase_started.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                if (options.inject_late_error_ms) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(options.inject_late_error_ms));
                    throw ClientError("injected late error after requested deadline");
                }
                const auto deadline = SteadyClock::time_point(
                    std::chrono::nanoseconds(phase_deadline_ns.load()));
                while (!stop.load() && SteadyClock::now() < deadline) {
                    const auto start = SteadyClock::now();
                    try {
                        auto connection = connect_client(config, options.timeout_ms);
                        const Result result = execute_workload(*connection, workload);
                        out.tls_used = result.tls_used;
                        out.ssl_in_use = result.ssl_in_use;
                        out.gssenc_in_use = result.gssenc_in_use;
                        out.tcp_nodelay = result.tcp_nodelay;
                        out.compression = result.compression;
                        out.ssl_cipher = result.ssl_cipher;
                        out.handshake_server_id = result.handshake_server_id;
                        if (out.local_port.empty()) out.local_port = result.local_port;
                        connection.reset();
                        const auto end = SteadyClock::now();
                        out.connect_latencies_ns.push_back(elapsed_ns(start, end));
                        ++out.cycles;
                    } catch (const std::exception& exc) {
                        out.error = exc.what();
                        failed = true;
                        stop = true;
                        break;
                    }
                }
            } catch (const std::exception& exc) {
                out.error = exc.what();
                failed = true;
                stop = true;
            }
        });
    }
    gate.arrive_and_wait();
    const auto phase_start = SteadyClock::now();
    const auto phase_deadline = phase_start + std::chrono::milliseconds(
        static_cast<long>(options.duration_seconds * 1000.0));
    phase_start_ns.store(phase_start.time_since_epoch().count());
    phase_deadline_ns.store(phase_deadline.time_since_epoch().count());
    phase_started.store(true, std::memory_order_release);
    for (auto& thread : threads) thread.join();
    const auto phase_end = SteadyClock::now();
    const double actual_elapsed = static_cast<double>(elapsed_ns(phase_start, phase_end)) / 1e9;

    std::uint64_t cycles = 0;
    std::vector<std::uint64_t> latencies;
    for (const auto& out : outcomes) {
        cycles += out.cycles;
        latencies.insert(latencies.end(), out.connect_latencies_ns.begin(),
                         out.connect_latencies_ns.end());
    }
    std::ostringstream json;
    json << "{\"ok\":" << (!failed && cycles > 0 ? "true" : "false")
         << ",\"mode\":\"connections\",\"protocol\":" << quote(config.protocol)
         << ",\"clients\":" << options.clients
         << ",\"payload_bytes\":" << workload.expected.size()
         << workload_json(workload)
         << ",\"requested_duration_s\":" << options.duration_seconds
         << ",\"actual_elapsed_s\":" << actual_elapsed
         << ",\"duration_s\":" << actual_elapsed << ",\"cycles\":" << cycles
         << ",\"connections_per_s\":"
         << (actual_elapsed > 0 ? cycles / actual_elapsed : 0)
         << ",\"p50_ns\":" << percentile(latencies, 0.50)
         << ",\"p95_ns\":" << percentile(latencies, 0.95)
         << ",\"p99_ns\":" << percentile(latencies, 0.99)
         << ",\"threads\":[";
    for (std::size_t i = 0; i < outcomes.size(); ++i) {
        if (i) json << ",";
        json << "{\"index\":" << i << ",\"cycles\":" << outcomes[i].cycles
             << ",\"local_port\":" << quote(outcomes[i].local_port)
             << ",\"tls_used\":" << (outcomes[i].tls_used ? "true" : "false")
             << ",\"ssl_in_use\":" << (outcomes[i].ssl_in_use ? "true" : "false")
             << ",\"gssenc_in_use\":" << (outcomes[i].gssenc_in_use ? "true" : "false")
             << ",\"tcp_nodelay\":" << outcomes[i].tcp_nodelay
             << ",\"compression\":" << (outcomes[i].compression ? "true" : "false")
             << ",\"handshake_server_id\":" << outcomes[i].handshake_server_id
             << ",\"error\":" << quote(outcomes[i].error) << "}";
    }
    json << "]";
    bool tls_used = false, ssl_in_use = false, gssenc_in_use = false, compression = false;
    int tcp_nodelay = -1;
    std::string ssl_cipher;
    for (const auto& out : outcomes) {
        tls_used = tls_used || out.tls_used;
        ssl_in_use = ssl_in_use || out.ssl_in_use;
        gssenc_in_use = gssenc_in_use || out.gssenc_in_use;
        compression = compression || out.compression;
        if (tcp_nodelay == -1) tcp_nodelay = out.tcp_nodelay;
        if (ssl_cipher.empty()) ssl_cipher = out.ssl_cipher;
    }
    json << ",\"tls_used\":" << (tls_used ? "true" : "false")
         << ",\"ssl_in_use\":" << (ssl_in_use ? "true" : "false")
         << ",\"gssenc_in_use\":" << (gssenc_in_use ? "true" : "false")
         << ",\"tcp_nodelay\":" << tcp_nodelay
         << ",\"compression\":" << (compression ? "true" : "false")
         << ",\"ssl_cipher\":" << quote(ssl_cipher)
         << ",\"library_versions\":" << library_versions_json();
    const std::string errors = thread_errors(outcomes);
    if (!errors.empty()) json << ",\"error\":" << quote(errors);
    json << "}";
    std::cout << json.str() << std::endl;
    return (!failed && cycles > 0) ? 0 : 1;
}

int run_throughput(const Config& config, const Options& options) {
    StartGate gate(options.clients);
    std::vector<ThreadOutcome> outcomes(options.clients);
    std::vector<std::thread> threads;
    const WorkloadSpec workload = build_workload(options);
    const std::string payload = workload.expected;
    const std::string sql = workload.select1 ? workload.sql : build_sql(payload);
    std::atomic<bool> failed {false};
    std::atomic<bool> stop {false};
    std::atomic<bool> phase_started {false};
    std::atomic<std::int64_t> phase_start_ns {0};
    std::atomic<std::int64_t> phase_deadline_ns {0};

    for (unsigned index = 0; index < options.clients; ++index) {
        threads.emplace_back([&, index]() {
            MysqlThreadGuard mysql_thread;
            ThreadOutcome& out = outcomes[index];
            bool arrived = false;
            try {
                auto connection = connect_client(config, options.timeout_ms);
                out.local_port = connection->local_port();
                for (std::size_t i = 0; i < options.warmups; ++i) {
                    const Result result = connection->query_only(sql, payload, false);
                    out.tls_used = result.tls_used;
                    out.ssl_in_use = result.ssl_in_use;
                    out.gssenc_in_use = result.gssenc_in_use;
                    out.tcp_nodelay = result.tcp_nodelay;
                    out.compression = result.compression;
                    out.ssl_cipher = result.ssl_cipher;
                    out.handshake_server_id = result.handshake_server_id;
                }
                gate.arrive_and_wait();
                arrived = true;
                while (!phase_started.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                if (options.inject_late_error_ms) {
                    std::this_thread::sleep_for(
                        std::chrono::milliseconds(options.inject_late_error_ms));
                    throw ClientError("injected late error after requested deadline");
                }
                const auto deadline = SteadyClock::time_point(
                    std::chrono::nanoseconds(phase_deadline_ns.load()));
                while (!stop.load() && SteadyClock::now() < deadline) {
                    const Result result = connection->query_only(sql, payload, false);
                    out.tls_used = result.tls_used;
                    out.ssl_in_use = result.ssl_in_use;
                    out.gssenc_in_use = result.gssenc_in_use;
                    out.tcp_nodelay = result.tcp_nodelay;
                    out.compression = result.compression;
                    out.ssl_cipher = result.ssl_cipher;
                    out.handshake_server_id = result.handshake_server_id;
                    ++out.queries;
                    out.request_bytes += payload.size();
                    out.response_bytes += payload.size();
                    out.sql_text_bytes += sql.size();
                }
            } catch (const std::exception& exc) {
                out.error = exc.what();
                failed = true;
                stop = true;
                if (!arrived) gate.arrive_and_wait();
            }
        });
    }
    gate.arrive_and_wait();
    const auto phase_start = SteadyClock::now();
    const auto phase_deadline = phase_start + std::chrono::milliseconds(
        static_cast<long>(options.duration_seconds * 1000.0));
    phase_start_ns.store(phase_start.time_since_epoch().count());
    phase_deadline_ns.store(phase_deadline.time_since_epoch().count());
    phase_started.store(true, std::memory_order_release);
    for (auto& thread : threads) thread.join();
    const auto phase_end = SteadyClock::now();
    const double actual_elapsed = static_cast<double>(elapsed_ns(phase_start, phase_end)) / 1e9;

    std::uint64_t queries = 0, request_bytes = 0, response_bytes = 0, sql_text_bytes = 0;
    for (const auto& out : outcomes) {
        queries += out.queries;
        request_bytes += out.request_bytes;
        response_bytes += out.response_bytes;
        sql_text_bytes += out.sql_text_bytes;
    }
    std::ostringstream json;
    json << "{\"ok\":" << (!failed && queries > 0 ? "true" : "false")
         << ",\"mode\":\"throughput\",\"protocol\":" << quote(config.protocol)
         << ",\"clients\":" << options.clients << ",\"payload_bytes\":"
         << payload.size() << ",\"payload_fnv1a64\":" << quote(hex64(fnv1a64(payload)))
         << workload_json(workload)
         << ",\"requested_duration_s\":" << options.duration_seconds
         << ",\"actual_elapsed_s\":" << actual_elapsed
         << ",\"duration_s\":" << actual_elapsed
         << ",\"queries\":" << queries << ",\"queries_per_s\":"
         << (actual_elapsed > 0 ? queries / actual_elapsed : 0)
         << ",\"application_request_bytes\":" << request_bytes
         << ",\"application_response_bytes\":" << response_bytes
         << ",\"application_request_mib_per_s\":"
         << (actual_elapsed > 0 ? (request_bytes / (1024.0 * 1024.0)) / actual_elapsed : 0)
         << ",\"application_response_mib_per_s\":"
         << (actual_elapsed > 0 ? (response_bytes / (1024.0 * 1024.0)) / actual_elapsed : 0)
         << ",\"sql_text_bytes\":" << sql_text_bytes
         << ",\"threads\":[";
    for (std::size_t i = 0; i < outcomes.size(); ++i) {
        if (i) json << ",";
        json << "{\"index\":" << i << ",\"queries\":" << outcomes[i].queries
             << ",\"local_port\":" << quote(outcomes[i].local_port)
             << ",\"tls_used\":" << (outcomes[i].tls_used ? "true" : "false")
             << ",\"ssl_in_use\":" << (outcomes[i].ssl_in_use ? "true" : "false")
             << ",\"gssenc_in_use\":" << (outcomes[i].gssenc_in_use ? "true" : "false")
             << ",\"tcp_nodelay\":" << outcomes[i].tcp_nodelay
             << ",\"compression\":" << (outcomes[i].compression ? "true" : "false")
             << ",\"handshake_server_id\":" << outcomes[i].handshake_server_id
             << ",\"error\":" << quote(outcomes[i].error) << "}";
    }
    json << "]";
    bool tls_used = false, ssl_in_use = false, gssenc_in_use = false, compression = false;
    int tcp_nodelay = -1;
    std::string ssl_cipher;
    for (const auto& out : outcomes) {
        tls_used = tls_used || out.tls_used;
        ssl_in_use = ssl_in_use || out.ssl_in_use;
        gssenc_in_use = gssenc_in_use || out.gssenc_in_use;
        compression = compression || out.compression;
        if (tcp_nodelay == -1) tcp_nodelay = out.tcp_nodelay;
        if (ssl_cipher.empty()) ssl_cipher = out.ssl_cipher;
    }
    json << ",\"tls_used\":" << (tls_used ? "true" : "false")
         << ",\"ssl_in_use\":" << (ssl_in_use ? "true" : "false")
         << ",\"gssenc_in_use\":" << (gssenc_in_use ? "true" : "false")
         << ",\"tcp_nodelay\":" << tcp_nodelay
         << ",\"compression\":" << (compression ? "true" : "false")
         << ",\"ssl_cipher\":" << quote(ssl_cipher)
         << ",\"library_versions\":" << library_versions_json();
    const std::string errors = thread_errors(outcomes);
    if (!errors.empty()) json << ",\"error\":" << quote(errors);
    json << "}";
    std::cout << json.str() << std::endl;
    return (!failed && queries > 0) ? 0 : 1;
}

int run_negative_timeout(const Config& config, const Options& options) {
    const std::string sql = options.negative_timeout_completes
        ? "SELECT 1"
        : (config.protocol == "mysql" ? "SELECT SLEEP(2)" : "SELECT pg_sleep(2)");
    auto connection = connect_client(config, options.timeout_ms);
    const auto start = SteadyClock::now();
    try {
        connection->query_only(sql, "unreachable", false);
    } catch (const std::exception& exc) {
        const auto elapsed_ms = static_cast<unsigned>(
            elapsed_ns(start, SteadyClock::now()) / 1000000ULL);
        const std::string message = exc.what();
        const bool timeout_word = message.find("timeout") != std::string::npos ||
                                  message.find("timed out") != std::string::npos;
        const bool mysql_read_timeout = config.protocol == "mysql" &&
            (message.find("Lost connection") != std::string::npos ||
             message.find("2013") != std::string::npos);
        const unsigned maximum_ms = std::max(4000U, options.timeout_ms + 2000U);
        const bool timed_out = !options.negative_timeout_completes &&
            (timeout_word || mysql_read_timeout) &&
            elapsed_ms >= 50U && elapsed_ms <= maximum_ms;
        std::cout << "{\"ok\":" << (timed_out ? "true" : "false")
                  << ",\"mode\":\"negative-timeout\",\"timed_out\":"
                  << (timed_out ? "true" : "false")
                  << ",\"elapsed_ms\":" << elapsed_ms
                  << ",\"timeout_bound_ms\":" << maximum_ms
                  << ",\"sql\":" << quote(options.negative_timeout_completes
                                             ? "completed-control" : "slow-query")
                  << ",\"error\":" << quote(message) << "}" << std::endl;
        return timed_out ? 0 : 1;
    }
    const auto elapsed_ms = static_cast<unsigned>(
        elapsed_ns(start, SteadyClock::now()) / 1000000ULL);
    std::cout << "{\"ok\":false,\"mode\":\"negative-timeout\",\"timed_out\":false,"
              << "\"elapsed_ms\":" << elapsed_ms
              << ",\"error\":\"slow query unexpectedly completed without a timeout\"}"
              << std::endl;
    return 1;
}

void usage() {
    std::cout
        << "usage: fast_forward_bench_client --config FILE --mode MODE [options]\n"
        << "\n"
        << "Modes: verify, hold, rtt, connections, throughput, negative-timeout\n"
        << "Config keys (0600 file): protocol, host, port, user, password, database\n"
        << "\n"
        << "Options:\n"
        << "  --workload literal|select1  literal (default) or exact SELECT 1\n"
        << "  --payload-bytes N       literal result payload size (default 64)\n"
        << "  --warmups N             warmup queries per client\n"
        << "  --samples N             RTT samples per client\n"
        << "  --clients N             native client threads (default 1)\n"
        << "  --duration-seconds S    connections/throughput phase duration\n"
        << "  --timeout-ms N          connect/read/write/query timeout\n"
        << "  --hold-seconds N        hold upper bound\n"
        << "  --corrupt-expectation   selfcheck only: expect one altered byte\n"
        << "  --negative-timeout-test selfcheck only: issue a bounded slow query\n"
        << "  --negative-timeout-completes selfcheck control: prove non-timeout is rejected\n"
        << "  --versions              print linked client library versions and exit\n"
        << "  --inject-late-error-ms N selfcheck only: fail after N ms\n"
        << "  --help                  show this help\n";
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto value = [&](const char* name) -> std::string {
            if (i + 1 >= argc) throw ClientError(std::string("missing value for ") + name);
            return argv[++i];
        };
        if (arg == "--help" || arg == "-h") {
            usage();
            std::exit(0);
        } else if (arg == "--config") {
            options.config_path = value("--config");
        } else if (arg == "--mode") {
            options.mode = value("--mode");
        } else if (arg == "--workload") {
            options.workload = value("--workload");
        } else if (arg == "--payload-bytes") {
            options.payload_bytes = std::stoul(value("--payload-bytes"));
        } else if (arg == "--warmups") {
            options.warmups = std::stoul(value("--warmups"));
        } else if (arg == "--samples") {
            options.samples = std::stoul(value("--samples"));
        } else if (arg == "--clients") {
            options.clients = static_cast<unsigned>(std::stoul(value("--clients")));
        } else if (arg == "--duration-seconds") {
            options.duration_seconds = std::stod(value("--duration-seconds"));
        } else if (arg == "--timeout-ms") {
            options.timeout_ms = static_cast<unsigned>(std::stoul(value("--timeout-ms")));
        } else if (arg == "--hold-seconds") {
            options.hold_seconds = static_cast<unsigned>(std::stoul(value("--hold-seconds")));
        } else if (arg == "--corrupt-expectation") {
            options.corrupt_expectation = true;
        } else if (arg == "--negative-timeout-test") {
            options.negative_timeout_test = true;
        } else if (arg == "--negative-timeout-completes") {
            options.negative_timeout_completes = true;
        } else if (arg == "--versions") {
            options.versions = true;
        } else if (arg == "--inject-late-error-ms") {
            options.inject_late_error_ms = static_cast<unsigned>(
                std::stoul(value("--inject-late-error-ms")));
        } else {
            throw ClientError("unknown argument: " + arg);
        }
    }
    if (options.config_path.empty() && !options.versions) {
        throw ClientError("--config is required");
    }
    if (options.clients == 0 || options.clients > 256) {
        throw ClientError("--clients must be between 1 and 256");
    }
    if (options.payload_bytes == 0 || options.payload_bytes > 64UL * 1024UL * 1024UL) {
        throw ClientError("--payload-bytes out of range");
    }
    if (options.workload != "literal" && options.workload != "select1") {
        throw ClientError("--workload must be literal or select1");
    }
    if (options.mode != "verify" && options.mode != "hold" &&
        options.mode != "rtt" && options.mode != "connections" &&
        options.mode != "throughput" && options.mode != "negative-timeout") {
        throw ClientError("invalid --mode");
    }
    return options;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parse_options(argc, argv);
        MysqlLibraryGuard mysql_library;
        if (!mysql_library.active_) throw ClientError("mysql_library_init failed");
        if (options.versions) {
            std::cout << library_versions_json() << std::endl;
            return 0;
        }
        const Config config = load_config(options.config_path);
        if (options.negative_timeout_test || options.mode == "negative-timeout") {
            return run_negative_timeout(config, options);
        }
        if (options.mode == "rtt") return run_rtt(config, options);
        if (options.mode == "connections") return run_connections(config, options);
        if (options.mode == "throughput") return run_throughput(config, options);

        const WorkloadSpec workload = build_workload(options);
        auto connection = connect_client(config, options.timeout_ms);
        const auto start = SteadyClock::now();
        const Result result = execute_workload(*connection, workload,
                                               options.corrupt_expectation);
        const auto end = SteadyClock::now();
        if (options.mode == "hold") {
            emit_ready(result, workload, options.hold_seconds);
            pollfd stdin_poll {STDIN_FILENO, POLLIN, 0};
            const int wait_ms = static_cast<int>(
                std::min(options.hold_seconds * 1000U, 60000U));
            const int ready = poll(&stdin_poll, 1, wait_ms);
            if (ready > 0 && (stdin_poll.revents & (POLLIN | POLLHUP))) {
                std::string line;
                std::getline(std::cin, line);
            }
            return 0;
        }
        emit_connection(result, workload, elapsed_ns(start, end));
        return 0;
    } catch (const std::exception& exc) {
        std::cout << "{\"ok\":false,\"error\":" << quote(exc.what()) << "}" << std::endl;
        return 1;
    }
}
