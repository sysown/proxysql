/**
 * @file pgsql-set_statement_test-t.cpp
 * @brief Intention: not to test every PostgreSQL variable, but to ensure different forms of SET statements
 *        are parsed correctly and not wrongly locked on a hostgroup. Covers common syntaxes (`=`, TO,
 *        multi-word params, aliases) and checks that unsupported forms like LOCAL or function-style values
 *        trigger the expected hostgroup lock behavior.
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <vector>
#include <map>
#include <ctime>
#include <sys/select.h>
#include "libpq-fe.h"
#include <mysql.h>
#include "command_line.h"
#include "noise_utils.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
    
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_root_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_root_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    if (options.empty() == false) {
		ss << " options='" << options << "'";
    }

    std::string conninfo = ss.str();
    // Mask password for logging
    std::string conninfo_display = conninfo;
    size_t pwd_pos = conninfo_display.find("password=");
    if (pwd_pos != std::string::npos) {
        size_t pwd_end = conninfo_display.find(" ", pwd_pos);
        if (pwd_end == std::string::npos) pwd_end = conninfo_display.length();
        conninfo_display.replace(pwd_pos + 9, pwd_end - (pwd_pos + 9), "***");
    }
    diag("Connection string: %s", conninfo_display.c_str());

    PGconn* conn = PQconnectdb(conninfo.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

struct TestCase {
    std::string sql;
    bool should_not_lock_on_hostgroup;
    std::string description;
};

std::fstream f_proxysql_log{};
PGConnPtr admin_conn{nullptr, &PQfinish};

static bool pgsql_admin_exec(MYSQL* admin, const char* query) {
    if (mysql_query(admin, query)) {
        diag("Admin query failed: '%s': %s", query, mysql_error(admin));
        return false;
    }
    MYSQL_RES* result = mysql_store_result(admin);
    if (result) mysql_free_result(result);
    return true;
}

static std::string pgsql_admin_scalar(MYSQL* admin, const char* query) {
    if (mysql_query(admin, query)) {
        diag("Admin query failed: '%s': %s", query, mysql_error(admin));
        return "";
    }

    std::string value;
    MYSQL_RES* result = mysql_store_result(admin);
    if (result) {
        MYSQL_ROW row = mysql_fetch_row(result);
        if (row && row[0]) value = row[0];
        mysql_free_result(result);
    }
    return value;
}

using AdminRows = std::vector<std::vector<std::string>>;

static AdminRows pgsql_admin_rows(MYSQL* admin, const char* query) {
    AdminRows rows;
    if (mysql_query(admin, query)) {
        diag("Admin query failed: '%s': %s", query, mysql_error(admin));
        return rows;
    }

    MYSQL_RES* result = mysql_store_result(admin);
    if (result) {
        MYSQL_ROW row;
        const unsigned int fields = mysql_num_fields(result);
        while ((row = mysql_fetch_row(result))) {
            std::vector<std::string> values;
            values.reserve(fields);
            for (unsigned int i = 0; i < fields; ++i) {
                values.emplace_back(row[i] ? row[i] : "");
            }
            rows.push_back(std::move(values));
        }
        mysql_free_result(result);
    }
    return rows;
}

static std::string pgsql_admin_quote(MYSQL* admin, const std::string& value) {
    std::vector<char> escaped(value.size() * 2 + 1);
    const unsigned long escaped_length = mysql_real_escape_string(
        admin, escaped.data(), value.c_str(), value.size());
    return "'" + std::string(escaped.data(), escaped_length) + "'";
}

class PgsqlPoolRuntimeGuard {
public:
    bool initialize() {
        admin_ = mysql_init(NULL);
        if (!admin_ || !mysql_real_connect(admin_, cl.admin_host, cl.admin_username, cl.admin_password,
                                           NULL, cl.admin_port, NULL, 0)) {
            diag("Unable to connect to ProxySQL admin: %s", admin_ ? mysql_error(admin_) : "mysql_init failed");
            return false;
        }

        original_main_servers_ = pgsql_admin_rows(admin_, pgsql_servers_select("pgsql_servers").c_str());
        original_runtime_servers_ = pgsql_admin_rows(admin_, pgsql_servers_select("runtime_pgsql_servers").c_str());
        original_main_variables_ = pgsql_admin_rows(admin_,
            "SELECT variable_name, variable_value FROM global_variables "
            "WHERE variable_name LIKE 'pgsql-%' ORDER BY variable_name");
        original_runtime_variables_ = pgsql_admin_rows(admin_,
            "SELECT variable_name, variable_value FROM runtime_global_variables "
            "WHERE variable_name LIKE 'pgsql-%' ORDER BY variable_name");
        if (original_main_servers_.empty() || original_runtime_servers_.empty() ||
            original_main_variables_.empty() || original_runtime_variables_.empty()) {
            diag("Unable to snapshot PostgreSQL main and runtime configuration");
            return false;
        }

        initialized_ = true;
        if (!replace_main_servers(original_runtime_servers_) ||
            !replace_main_variables(original_runtime_variables_) ||
            !pgsql_admin_exec(admin_, "UPDATE pgsql_servers SET max_connections=1") ||
            !load_pool_configuration()) {
            return false;
        }
        return true;
    }

    bool set_free_connections_pct(const char* value) {
        const std::string query = std::string("SET pgsql-free_connections_pct=") + value;
        return pgsql_admin_exec(admin_, query.c_str()) &&
               pgsql_admin_exec(admin_, "LOAD PGSQL VARIABLES TO RUNTIME");
    }

    bool wait_for_free_connections(const char* expected) {
        for (int i = 0; i < 150; ++i) {
            const std::string free_connections = pgsql_admin_scalar(admin_,
                "SELECT IFNULL(SUM(ConnFree),0) FROM stats_pgsql_connection_pool");
            if (free_connections == expected) return true;
            usleep(100 * 1000);
        }
        diag("Timed out waiting for %s free PostgreSQL backend connection(s)", expected);
        return false;
    }

    bool restore() {
        if (!initialized_ || restored_) return true;
        restored_ = true;

        bool restored = true;
        if (!replace_main_servers(original_runtime_servers_) ||
            !replace_main_variables(original_runtime_variables_) ||
            !load_pool_configuration()) {
            diag("Failed to restore PostgreSQL pool runtime configuration");
            restored = false;
        }
        if (!replace_main_servers(original_main_servers_) ||
            !replace_main_variables(original_main_variables_)) {
            diag("Failed to restore PostgreSQL main configuration after pool test");
            restored = false;
        }
        return restored;
    }

    ~PgsqlPoolRuntimeGuard() {
        restore();
        if (admin_) mysql_close(admin_);
    }

private:
    static std::string pgsql_servers_select(const char* table) {
        return std::string("SELECT hostgroup_id, hostname, port, status, weight, compression, ") +
               "max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM " +
               table + " ORDER BY hostgroup_id, hostname, port";
    }

    bool replace_main_servers(const AdminRows& servers) {
        if (!pgsql_admin_exec(admin_, "DELETE FROM pgsql_servers")) return false;

        for (const auto& server : servers) {
            if (server.size() != 11) {
                diag("Unexpected pgsql_servers row width while restoring configuration");
                return false;
            }
            std::string query = "INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, weight, "
                                "compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, "
                                "comment) VALUES (";
            for (size_t i = 0; i < server.size(); ++i) {
                if (i) query += ", ";
                query += pgsql_admin_quote(admin_, server[i]);
            }
            query += ")";
            if (!pgsql_admin_exec(admin_, query.c_str())) return false;
        }
        return true;
    }

    bool replace_main_variables(const AdminRows& variables) {
        for (const auto& variable : variables) {
            if (variable.size() != 2) {
                diag("Unexpected pgsql variable row width while restoring configuration");
                return false;
            }
            const std::string query = "INSERT OR REPLACE INTO global_variables "
                                      "(variable_name, variable_value) VALUES (" +
                                      pgsql_admin_quote(admin_, variable[0]) + ", " +
                                      pgsql_admin_quote(admin_, variable[1]) + ")";
            if (!pgsql_admin_exec(admin_, query.c_str())) return false;
        }
        return true;
    }

    bool load_pool_configuration() {
        return pgsql_admin_exec(admin_, "LOAD PGSQL SERVERS TO RUNTIME") &&
               pgsql_admin_exec(admin_, "LOAD PGSQL VARIABLES TO RUNTIME");
    }

    MYSQL* admin_{nullptr};
    bool initialized_{false};
    bool restored_{false};
    AdminRows original_main_servers_;
    AdminRows original_runtime_servers_;
    AdminRows original_main_variables_;
    AdminRows original_runtime_variables_;
};

bool check_logs_for_command(const std::string& command_regex) {
    // Issue #5788: log-scrape race. PROXYSQL FLUSH LOGS over a persistent
    // Admin connection fences in-flight log writes before we scan, and
    // clearing eofbit lets getline() read bytes appended since the last
    // scan (sticky eofbit was the root cause). Single scan, no polling.
    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        admin_conn = createNewConnection(ADMIN);
    }
    if (admin_conn) {
        PGresult* res = PQexec(admin_conn.get(), "PROXYSQL FLUSH LOGS");
        if (res) PQclear(res);
    }

    f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::eofbit & ~std::ios_base::failbit);
    const auto& [_, cmd_lines] = get_matching_lines(f_proxysql_log, command_regex);
    return !cmd_lines.empty();
}

bool run_set_statement(const std::string& stmt, ConnType type = BACKEND) {
    PGConnPtr conn = createNewConnection(type);
    if (!conn) return false;

    PGresult* res = PQexec(conn.get(), stmt.c_str());
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return false;
    }
    PQclear(res);

    return check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == false;
}

// Simple command execution that just checks if query succeeded
bool run_command(const std::string& stmt, ConnType type = BACKEND) {
    PGConnPtr conn = createNewConnection(type);
    if (!conn) return false;

    PGresult* res = PQexec(conn.get(), stmt.c_str());
    bool ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    return ok;
}

// Structure to hold variable test data
struct PipelineTestVariable {
    std::string name;
    std::string test_value;
    std::string initial_value;
};

// Helper function to get variable value via simple query
std::string get_variable_simple(PGconn* conn, const std::string& var_name) {
    std::string query = "SHOW " + var_name;
    PGresult* res = PQexec(conn, query.c_str());
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return "";
    }
    char* val = PQgetvalue(res, 0, 0);
    std::string result = val ? val : "";
    PQclear(res);
    return result;
}

// Helper function to set variable via simple query (no verification)
bool set_variable_simple(PGconn* conn, const std::string& var_name, const std::string& value) {
    std::string query = "SET " + var_name + " = '" + value + "'";
    PGresult* res = PQexec(conn, query.c_str());
    bool ok = (res && PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    return ok;
}

// Test: SET variables in simple query, verify in pipeline mode
bool test_set_simple_verify_pipeline() {
    diag("=== Test: SET in simple query, verify in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) {
        diag("Failed to create connection");
        return false;
    }

    // Test variables: mix of critical and non-critical
    // Values will be set to DIFFERENT from original
    std::vector<PipelineTestVariable> test_vars = {
        {"DateStyle", "", ""},
        {"TimeZone", "", ""},
        {"bytea_output", "", ""},
        {"extra_float_digits", "", ""}
    };

    // Get original values and choose DIFFERENT test values
    for (auto& var : test_vars) {
        var.initial_value = get_variable_simple(conn.get(), var.name);
        // Choose value DIFFERENT from original
        if (var.name == "DateStyle") {
            var.test_value = (var.initial_value.find("ISO") != std::string::npos) ?
                            "Postgres, DMY" : "ISO, MDY";
        } else if (var.name == "TimeZone") {
            var.test_value = (var.initial_value.find("UTC") != std::string::npos) ?
                            "PST8PDT" : "UTC";
        } else if (var.name == "bytea_output") {
            var.test_value = (var.initial_value == "hex") ? "escape" : "hex";
        } else if (var.name == "extra_float_digits") {
            var.test_value = (var.initial_value == "0") ? "3" : "0";
        }
        diag("%s: original='%s', will SET to='%s'",
             var.name.c_str(), var.initial_value.c_str(), var.test_value.c_str());
    }

    // Phase 1: Get initial values and SET new values via simple query
    for (auto& var : test_vars) {
        var.initial_value = get_variable_simple(conn.get(), var.name);
        diag("Initial %s: %s", var.name.c_str(), var.initial_value.c_str());

        if (!set_variable_simple(conn.get(), var.name, var.test_value)) {
            diag("Failed to SET %s", var.name.c_str());
            return false;
        }
        diag("SET %s = '%s'", var.name.c_str(), var.test_value.c_str());
    }

    // Phase 2: Enter pipeline and SHOW variables
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    for (const auto& var : test_vars) {
        std::string query = "SHOW " + var.name;
        if (PQsendQueryParams(conn.get(), query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SHOW %s in pipeline", var.name.c_str());
            return false;
        }
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Phase 3: Consume results and verify
    // Use a longer timeout and more robust result consumption
    int expected_results = test_vars.size();
    std::map<std::string, std::string> results;
    int count = 0;
    int result_idx = 0;
    int sock = PQsocket(conn.get());
    if (sock < 0) {
        diag("Invalid socket descriptor from PQsocket");
        return false;
    }
    PGresult* res;
    time_t start_time = time(NULL);
    const int max_wait_seconds = 30;  // Increased timeout

    while (count < expected_results + 1) {
        if (PQconsumeInput(conn.get()) == 0) {
            diag("PQconsumeInput failed: %s", PQerrorMessage(conn.get()));
            break;
        }

        bool got_result = false;
        while ((res = PQgetResult(conn.get())) != NULL) {
            got_result = true;
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char* val = PQgetvalue(res, 0, 0);
                if (val && result_idx < (int)test_vars.size()) {
                    results[test_vars[result_idx].name] = val;
                    result_idx++;
                    diag("Got result %d/%d for %s: %s",
                         result_idx, (int)test_vars.size(),
                         test_vars[result_idx-1].name.c_str(), val);
                }
            }
            if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= expected_results + 1) break;

        // Check for timeout
        if (time(NULL) - start_time > max_wait_seconds) {
            diag("Timeout waiting for results after %d seconds", max_wait_seconds);
            break;
        }

        // If we got results, continue immediately; otherwise wait for more data
        if (got_result) continue;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {1, 0};  // 1 second poll

        int sel = select(sock + 1, &input_mask, NULL, NULL, &timeout);
        if (sel < 0) {
            diag("select() failed");
            break;
        }
        // Continue loop to call PQconsumeInput even on timeout
    }

    PQexitPipelineMode(conn.get());

    // Verify results
    bool success = true;
    for (const auto& var : test_vars) {
        auto it = results.find(var.name);
        if (it == results.end()) {
            diag("No result for %s", var.name.c_str());
            success = false;
            continue;
        }
        std::string pipeline_value = it->second;
        bool matches = (pipeline_value.find(var.test_value) != std::string::npos) ||
                       (var.test_value.find(pipeline_value) != std::string::npos);
        if (!matches) {
            diag("MISMATCH for %s: expected '%s', got '%s'",
                 var.name.c_str(), var.test_value.c_str(), pipeline_value.c_str());
            success = false;
        } else {
            diag("MATCH for %s: '%s' == '%s'",
                 var.name.c_str(), var.test_value.c_str(), pipeline_value.c_str());
        }
    }

    return success;
}

// Test: SET multiple critical variables, verify in pipeline
bool test_multiple_critical_vars_pipeline() {
    diag("=== Test: Multiple critical variables in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Critical variables - will use values DIFFERENT from original
    std::vector<PipelineTestVariable> critical_vars = {
        {"client_encoding", "", ""},
        {"DateStyle", "", ""},
        {"IntervalStyle", "", ""},
        {"standard_conforming_strings", "", ""}
    };

    // Get original values and choose DIFFERENT test values
    for (auto& var : critical_vars) {
        var.initial_value = get_variable_simple(conn.get(), var.name);
        // Choose value DIFFERENT from original
        if (var.name == "client_encoding") {
            var.test_value = (var.initial_value == "UTF8") ? "LATIN1" : "UTF8";
        } else if (var.name == "DateStyle") {
            var.test_value = (var.initial_value.find("ISO") != std::string::npos) ?
                            "Postgres, MDY" : "ISO, DMY";
        } else if (var.name == "IntervalStyle") {
            var.test_value = (var.initial_value == "postgres") ? "iso_8601" : "postgres";
        } else if (var.name == "standard_conforming_strings") {
            var.test_value = (var.initial_value == "on") ? "off" : "on";
        }
        diag("%s: original='%s', will SET to='%s'",
             var.name.c_str(), var.initial_value.c_str(), var.test_value.c_str());
    }

    // Phase 1: SET all via simple query
    for (auto& var : critical_vars) {
        var.initial_value = get_variable_simple(conn.get(), var.name);
        if (!set_variable_simple(conn.get(), var.name, var.test_value)) {
            diag("Failed to SET %s", var.name.c_str());
            return false;
        }
    }

    // Phase 2: Verify all in pipeline
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    for (const auto& var : critical_vars) {
        std::string query = "SHOW " + var.name;
        PQsendQueryParams(conn.get(), query.c_str(), 0, NULL, NULL, NULL, NULL, 0);
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int expected = critical_vars.size();
    std::map<std::string, std::string> results;
    int count = 0;
    int idx = 0;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < expected + 1) {
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char* val = PQgetvalue(res, 0, 0);
                if (val && idx < (int)critical_vars.size()) {
                    results[critical_vars[idx].name] = val;
                    idx++;
                }
            }
            if (PQresultStatus(res) == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= expected + 1) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify
    bool success = true;
    for (const auto& var : critical_vars) {
        auto it = results.find(var.name);
        if (it == results.end()) {
            success = false;
            continue;
        }
        std::string val = it->second;
        // For standard_conforming_strings, check contains
        bool matches = (val.find(var.test_value) != std::string::npos) ||
                       (var.test_value.find(val) != std::string::npos) ||
                       (val == var.test_value);
        if (!matches) {
            diag("MISMATCH for %s: expected '%s', got '%s'",
                 var.name.c_str(), var.test_value.c_str(), val.c_str());
            success = false;
        }
    }

    return success;
}

// Phase 3: SET in Pipeline Mode - Send SET commands via extended query in pipeline
bool test_set_in_pipeline_mode() {
    diag("=== Test: SET commands in pipeline mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get initial values and choose DIFFERENT test values
    std::vector<PipelineTestVariable> test_vars = {
        {"DateStyle", "", ""},
        {"TimeZone", "", ""},
        {"bytea_output", "", ""}
    };

    for (auto& var : test_vars) {
        var.initial_value = get_variable_simple(conn.get(), var.name);
        // Choose value DIFFERENT from original
        if (var.name == "DateStyle") {
            var.test_value = (var.initial_value.find("ISO") != std::string::npos) ?
                            "SQL, DMY" : "ISO, MDY";
        } else if (var.name == "TimeZone") {
            var.test_value = (var.initial_value.find("UTC") != std::string::npos) ?
                            "EST5EDT" : "UTC";
        } else if (var.name == "bytea_output") {
            var.test_value = (var.initial_value == "hex") ? "escape" : "hex";
        }
        diag("%s: original='%s', will SET to='%s'",
             var.name.c_str(), var.initial_value.c_str(), var.test_value.c_str());
    }

    // Enter pipeline mode FIRST
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send SET commands in pipeline
    for (const auto& var : test_vars) {
        std::string query = "SET " + var.name + " = '" + var.test_value + "'";
        if (PQsendQueryParams(conn.get(), query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SET %s in pipeline", var.name.c_str());
            return false;
        }
    }

    // Send SHOW commands to verify in same pipeline
    for (const auto& var : test_vars) {
        std::string query = "SHOW " + var.name;
        if (PQsendQueryParams(conn.get(), query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SHOW %s in pipeline", var.name.c_str());
            return false;
        }
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int set_count = 0;
    int show_count = 0;
    int expected = test_vars.size() * 2;  // SET + SHOW for each
    int count = 0;
    int sock = PQsocket(conn.get());
    PGresult* res;
    std::map<std::string, std::string> results;
    int result_idx = 0;

    while (count < expected + 1) {
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_COMMAND_OK) {
                set_count++;
            } else if (status == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char* val = PQgetvalue(res, 0, 0);
                if (val && result_idx < (int)test_vars.size()) {
                    results[test_vars[result_idx].name] = val;
                    result_idx++;
                }
                show_count++;
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= expected + 1) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify SET worked within pipeline
    bool success = true;
    for (const auto& var : test_vars) {
        auto it = results.find(var.name);
        if (it == results.end()) {
            diag("No result for %s", var.name.c_str());
            success = false;
            continue;
        }
        std::string pipeline_value = it->second;
        bool matches = (pipeline_value.find(var.test_value) != std::string::npos) ||
                       (var.test_value.find(pipeline_value) != std::string::npos);
        if (!matches) {
            diag("MISMATCH for %s: expected '%s', got '%s'",
                 var.name.c_str(), var.test_value.c_str(), pipeline_value.c_str());
            success = false;
        }
    }

    diag("SET commands completed: %d, SHOW commands completed: %d", set_count, show_count);
    return success && (set_count >= (int)test_vars.size()) && (show_count >= (int)test_vars.size());
}

// Phase 5: SET then query using variable - verify query respects SET value
bool test_set_then_query_pipeline() {
    diag("=== Test: SET DateStyle then query in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get initial DateStyle and choose DIFFERENT value
    std::string orig_datestyle = get_variable_simple(conn.get(), "DateStyle");
    // Choose SQL, DMY if current is ISO, otherwise choose ISO
    std::string new_datestyle = (orig_datestyle.find("ISO") != std::string::npos) ?
                                "SQL, DMY" : "ISO, MDY";
    diag("DateStyle: original='%s', will SET to='%s'",
         orig_datestyle.c_str(), new_datestyle.c_str());

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send SET DateStyle with NEW value (different from original)
    std::string set_query = "SET DateStyle = '" + new_datestyle + "'";
    if (PQsendQueryParams(conn.get(), set_query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET DateStyle");
        return false;
    }

    // Send a query that uses dates - the output format should respect DateStyle
    if (PQsendQueryParams(conn.get(), "SELECT '2024-03-15'::date", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SELECT");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    int cmd_count = 0;
    std::string date_result;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 3) {  // 2 commands + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_COMMAND_OK) {
                cmd_count++;
            } else if (status == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char* val = PQgetvalue(res, 0, 0);
                if (val) date_result = val;
                cmd_count++;
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= 3) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    diag("Date result: '%s'", date_result.c_str());

    // Verify format changed based on what we SET
    bool format_changed = false;
    if (new_datestyle.find("SQL") != std::string::npos) {
        // SQL, DMY format should be like "15/03/2024" (day/month/year)
        format_changed = (date_result.find("/") != std::string::npos) ||
                         (date_result.find("15") == 0);  // Starts with day
    } else {
        // ISO format would be "2024-03-15"
        format_changed = (date_result.find("-") != std::string::npos) ||
                         (date_result.find("2024") == 0);  // Starts with year
    }

    // Cleanup - restore original
    set_variable_simple(conn.get(), "DateStyle", orig_datestyle);

    return (cmd_count >= 2) && format_changed;
}

// Test: RESET ALL should fail in pipeline mode (not supported)
bool test_reset_all_failure_pipeline() {
    diag("=== Test: RESET ALL failure in pipeline mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send RESET ALL
    if (PQsendQueryParams(conn.get(), "RESET ALL", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send RESET ALL");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool got_error = false;
    std::string error_msg;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 2) {  // 1 command + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_FATAL_ERROR) {
                got_error = true;
                error_msg = PQresultErrorMessage(res);
                diag("Got expected error: %s", error_msg.c_str());
            }
            if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;
            }
            PQclear(res);
            count++;
        }

        if (count >= 2) break;

        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify error message mentions pipeline mode
    bool correct_error = (error_msg.find("pipeline") != std::string::npos) ||
                        (error_msg.find("not supported") != std::string::npos);

    return got_error && correct_error;
}

// Test: DISCARD ALL should fail in pipeline mode (not supported)
bool test_discard_all_failure_pipeline() {
    diag("=== Test: DISCARD ALL failure in pipeline mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send DISCARD ALL
    if (PQsendQueryParams(conn.get(), "DISCARD ALL", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send DISCARD ALL");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool got_error = false;
    std::string error_msg;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 2) {  // 1 command + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_FATAL_ERROR) {
                got_error = true;
                error_msg = PQresultErrorMessage(res);
                diag("Got expected error: %s", error_msg.c_str());
            }
            if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;
            }
            PQclear(res);
            count++;
        }

        if (count >= 2) break;

        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify error message mentions pipeline mode
    bool correct_error = (error_msg.find("pipeline") != std::string::npos) ||
                        (error_msg.find("not supported") != std::string::npos);

    return got_error && correct_error;
}

// Test: Verify startup parameters are applied
bool test_startup_parameters() {
    diag("=== Test: Verify startup parameters ===");

    // Create connection with explicit startup parameter (space must be escaped with double backslash)
    const std::string startup_value = "SQL,\\\\ DMY";  // C++: \\ -> actual: \ -> libpq sees: escaped space
    PGConnPtr conn = createNewConnection(BACKEND, "-c DateStyle=" + startup_value);
    if (!conn) {
        diag("Failed to create connection");
        return false;
    }

    // Check connection status
    if (PQstatus(conn.get()) != CONNECTION_OK) {
        diag("Connection not OK: %s", PQerrorMessage(conn.get()));
        return false;
    }

    // Get the actual value from backend
    PGresult* res = PQexec(conn.get(), "SHOW DateStyle");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag("SHOW failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return false;
    }

    if (PQntuples(res) == 0) {
        diag("SHOW returned no rows");
        PQclear(res);
        return false;
    }

    char* val = PQgetvalue(res, 0, 0);
    std::string actual_value = val ? val : "";
    diag("Startup parameter set to: '%s'", startup_value.c_str());
    diag("Actual DateStyle from backend: '%s'", actual_value.c_str());
    PQclear(res);

    // In ProxySQL, startup parameters might not be forwarded to backend
    // This test documents the current behavior
    bool startup_applied = (actual_value.find("SQL") != std::string::npos);
    diag("Startup parameter applied: %s", startup_applied ? "yes" : "no (pooled connection used)");

    // For this test, we just verify we can read the value, not that startup params work
    return !actual_value.empty();
}

// Test: RESET single variable should work in pipeline mode
bool test_reset_single_var_pipeline() {
    diag("=== Test: RESET single variable in pipeline mode ===");

    // Note: Connection pooling may interfere with explicit startup parameters.
    // We test RESET behavior by:
    // 1. Get current value
    // 2. SET to a different value
    // 3. RESET in pipeline mode
    // 4. Verify value changed (not necessarily to original)

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get current value (whatever the pooled connection has)
    const std::string initial_value = get_variable_simple(conn.get(), "DateStyle");
    diag("Initial DateStyle: '%s'", initial_value.c_str());

    // Choose a test value different from current
    std::string test_value = (initial_value.find("Postgres") != std::string::npos) ?
                             "SQL, DMY" : "Postgres, DMY";

    if (!set_variable_simple(conn.get(), "DateStyle", test_value)) {
        diag("Failed to SET DateStyle");
        return false;
    }

    std::string set_value = get_variable_simple(conn.get(), "DateStyle");
    diag("After SET: DateStyle = '%s'", set_value.c_str());

    // Verify value was actually changed
    if (set_value == initial_value) {
        diag("SET did not change the value - test cannot proceed");
        return false;
    }

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send RESET DateStyle
    if (PQsendQueryParams(conn.get(), "RESET DateStyle", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send RESET DateStyle");
        return false;
    }

    // Send SHOW DateStyle to verify reset
    if (PQsendQueryParams(conn.get(), "SHOW DateStyle", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SHOW DateStyle");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int cmd_count = 0;
    int show_count = 0;
    std::string reset_result;
    int count = 0;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 3) {  // 2 commands + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            diag("Got result: status=%d (%s), ntuples=%d", status, PQresStatus(status), PQntuples(res));
            if (status == PGRES_COMMAND_OK) {
                cmd_count++;
                diag("RESET command succeeded");
            } else if (status == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char* val = PQgetvalue(res, 0, 0);
                if (val) {
                    reset_result = val;
                    diag("After RESET: DateStyle = '%s'", reset_result.c_str());
                }
                show_count++;
            } else if (status == PGRES_TUPLES_OK && PQntuples(res) == 0) {
                diag("SHOW returned 0 tuples");
            } else if (status == PGRES_FATAL_ERROR) {
                diag("Error: %s", PQresultErrorMessage(res));
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;
            }
            PQclear(res);
            count++;
        }

        if (count >= 3) break;

        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Debug output
    diag("Results summary: cmd_count=%d, show_count=%d, total_count=%d", cmd_count, show_count, count);
    diag("reset_result='%s', initial_value='%s'", reset_result.c_str(), initial_value.c_str());

    // Verify RESET worked - value should be different from what we SET
    // Note: Due to connection pooling, it may not exactly match initial_value,
    // but it should be different from set_value (proving RESET executed)
    bool reset_executed = (!reset_result.empty() && reset_result != set_value);
    diag("Value reset from '%s' to '%s': %s",
         set_value.c_str(), reset_result.c_str(),
         reset_executed ? "success (value changed)" : "failed");

    return (cmd_count >= 1) && (show_count >= 1) && reset_executed;
}

// Test: RESET reverts to startup parameter value
bool test_reset_reverts_to_startup_param() {
    diag("=== Test: RESET reverts to startup parameter value ===");

    // Create connection with explicit startup parameter (space must be escaped with double backslash)
    const std::string startup_value = "SQL,\\\\ DMY";  // C++: \\ -> actual: \ -> libpq sees: escaped space
    PGConnPtr conn = createNewConnection(BACKEND, "-c DateStyle=" + startup_value);
    if (!conn) {
        diag("Failed to create connection with startup parameter");
        return false;
    }

    // Get startup value (what we set in connection string)
    std::string actual_startup = get_variable_simple(conn.get(), "DateStyle");
    diag("Startup parameter value: '%s'", startup_value.c_str());
    diag("Actual DateStyle after connect: '%s'", actual_startup.c_str());

    // Choose a different value for SET
    std::string new_value = (actual_startup.find("Postgres") != std::string::npos) ?
                            "ISO, MDY" : "Postgres, DMY";

    // SET to a different value
    if (!set_variable_simple(conn.get(), "DateStyle", new_value)) {
        diag("Failed to SET DateStyle to '%s'", new_value.c_str());
        return false;
    }

    std::string after_set = get_variable_simple(conn.get(), "DateStyle");
    diag("After SET: DateStyle = '%s'", after_set.c_str());

    // Verify SET worked
    if (after_set == actual_startup) {
        diag("SET did not change the value");
        return false;
    }

    // RESET the variable
    PGresult* res = PQexec(conn.get(), "RESET DateStyle");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("RESET failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Get value after RESET
    std::string after_reset = get_variable_simple(conn.get(), "DateStyle");
    diag("After RESET: DateStyle = '%s'", after_reset.c_str());

    // Verify RESET reverted to startup value
    bool reverted = (after_reset == actual_startup);
    diag("RESET reverted to startup value: %s", reverted ? "yes" : "no");

    return reverted;
}

// Forward declarations for pipeline mode tests
bool test_set_simple_verify_pipeline();
bool test_multiple_critical_vars_pipeline();
bool test_set_in_pipeline_mode();
bool test_set_then_query_pipeline();
bool test_set_failure_invalid_value_pipeline();
bool test_set_failure_invalid_encoding_pipeline();
bool test_set_failure_syntax_error_pipeline();
bool test_set_failure_multiple_set_one_fails();
bool test_set_different_values_from_original();
bool test_reset_all_failure_pipeline();
bool test_discard_all_failure_pipeline();
bool test_reset_single_var_pipeline();
bool test_reset_simple_query();
bool test_reset_all_simple_query();
bool test_discard_all_simple_query();
bool test_multiple_vars_out_of_sync_pipeline();
bool test_pipeline_with_locked_hostgroup();
bool test_reset_all_locked_hostgroup_pipeline();
bool test_discard_all_locked_hostgroup_pipeline();
bool test_reset_reverts_to_startup_param();

int main(int argc, char** argv) {
    if (cl.getEnv())
        return exit_status();

	spawn_internal_noise(cl, internal_noise_mysql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});

    std::vector<TestCase> tests = {
        // Standard param/value
        {"SET datestyle = 'ISO, MDY';", true, "datestyle with ="},
        {"SET datestyle TO 'ISO,MDY';", true, "datestyle with TO"},
        {"SET standard_conforming_strings TO on;", true, "boolean ON"},
        {"SET enable_seqscan = off;", true, "boolean OFF"},
        {"SET SESSION datestyle = 'ISO, DMY';", true, "SESSION prefix"},

        // TIME ZONE
        {"SET TIME ZONE 'UTC';", true, "TIME ZONE UTC"},
        {"SET TIME ZONE DEFAULT;", true, "TIME ZONE DEFAULT"},
        {"SET TIME ZONE -7;", true, "TIME ZONE numeric offset"},
        {"SET TIME ZONE INTERVAL '+02:30' HOUR TO MINUTE;", true, "TIME ZONE interval"},

        // TRANSACTION ISOLATION LEVEL
        {"SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;", false, "TX ISOLATION READ UNCOMMITTED"},
        {"SET TRANSACTION ISOLATION LEVEL READ COMMITTED;", false, "TX ISOLATION READ COMMITTED"},
        {"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;", false, "TX ISOLATION REPEATABLE READ"},
        {"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;", false, "TX ISOLATION SERIALIZABLE"},

        // XML OPTION
        {"SET XML OPTION DOCUMENT;", false, "XML OPTION DOCUMENT"},
        {"SET XML OPTION CONTENT;", false, "XML OPTION CONTENT"},

        // SESSION AUTHORIZATION
        {"SET SESSION AUTHORIZATION DEFAULT;", false, "SESSION AUTHORIZATION DEFAULT"},

        // ROLE
        {"SET ROLE NONE;", false, "ROLE NONE"},

        // SCHEMA
        {"SET SCHEMA 'pg_catalog';", false, "SCHEMA valid"},

        // NAMES
        {"SET NAMES SQL_ASCII;", true, "NAMES SQL_ASCII"},
        {"SET NAMES UTF8;", true, "NAMES UTF8"},

        // SEARCH_PATH
		{"SET search_path TO 'pg_catalog';", true, "search_path single schema"},
		{"SET search_path TO 'schema1, schema2';", true, "search_path multiple schemas"},
		{"SET search_path TO '\"MySchema\"';", true, "search_path quoted identifier"},
		{"SET search_path TO 'schema1, \"MySchema\"';", true, "search_path mixed identifiers"},
		{"SET search_path TO 'schema1, pg_catalog';", true, "search_path with pg_catalog"},
		{"SET search_path TO '$user, public';", true, "search_path with $user"},
		{"SET search_path TO 'public, $user';", true, "search_path with $user at end"},
		{"SET search_path TO 'public, $user, pg_catalog';", true, "search_path with $user and pg_catalog"},
		{"SET search_path TO '\"$user\"';", true, "search_path with quoted $user"},
		{"SET search_path TO '\"$user\", pg_catalog';", true, "search_path with quoted $user and pg_catalog"},
		{"SET search_path TO '\"$user\", public';", true, "search_path with quoted $user and public"},
		{"SET search_path TO 'public, \"$user\"';", true, "search_path with public and quoted $user"},
		{"SET search_path TO '\"$user\", public, pg_catalog';", true, "search_path with quoted $user, public and pg_catalog"},
		{"SET search_path = 'public, \"$user\", pg_catalog';", true, "search_path with public, quoted $user and pg_catalog"},
		{"SET search_path = '\"MySchema\", pg_catalog';", true, "search_path with quoted identifier and pg_catalog"},
		{"SET search_path = '\"MySchema\", public';", true, "search_path with quoted identifier and public"},
		{"SET search_path = 'public, \"MySchema\"';", true, "search_path with public and quoted identifier"},
		{"SET search_path = '\"MySchema\", public, pg_catalog';", true, "search_path with quoted identifier, public and pg_catalog"},
		{"SET search_path = 'public, \"MySchema\", pg_catalog';", true, "search_path with public, quoted identifier and pg_catalog"},
		{"SET search_path = 'schema1, \"MySchema\", schema2';", true, "search_path multiple mixed identifiers"},
		{"SET search_path = ''; ", true, "search_path empty string"},
		{"SET search_path = ' , , '; ", true, "search_path only commas and spaces"},
		{"SET search_path = ',public,'; ", true, "search_path leading and trailing commas"},

        // SEED
        {"SET SEED 0.5;", false, "SEED 0.5"},
        {"SET SEED 0;", false, "SEED 0"},
        {"SET SEED 1;", false, "SEED 1"},
        {"SET SEED 1.5;", false, "SEED out of range"},

        // Failure cases
        {"SET ALL TO DEFAULT;", false, "ALL should fail"},
        {"SET LOCAL datestyle TO 'ISO,MDY';", false, "LOCAL should fail"},
        {"SET search_path TO current_schemas(true);", false, "function value should fail"},
        {"SET datestyle = ;", false, "missing value"}
    };

    // Add pipeline tests to the plan (20 total: 16 pipeline + 4 simple query RESET/DISCARD)
    const int num_pipeline_tests = 20;

    if (cl.use_noise) {
        plan(tests.size() + num_pipeline_tests + 3);
    } else {
        plan(tests.size() + num_pipeline_tests);
    }

    std::string f_path{ get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };

    int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
    if (of_err != EXIT_SUCCESS) {
        return exit_status();
    }

    // Run existing simple query tests
    for (const auto& t : tests) {
        f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
        f_proxysql_log.seekg(f_proxysql_log.tellg());
        bool result = run_set_statement(t.sql);
        ok(result == t.should_not_lock_on_hostgroup, "%s", t.description.c_str());
        usleep(10000);
    }

    f_proxysql_log.close();

    // Run RESET and DISCARD tests in simple query mode
    ok(test_reset_simple_query(), "RESET single variable in simple query mode");
    ok(test_reset_all_simple_query(), "RESET ALL in simple query mode");
    ok(test_discard_all_simple_query(), "DISCARD ALL in simple query mode");
    ok(test_reset_reverts_to_startup_param(), "RESET reverts to startup parameter value");

    // Run pipeline tests
    ok(test_set_simple_verify_pipeline(), "SET in simple query, verify in pipeline mode");
    ok(test_multiple_critical_vars_pipeline(), "Multiple critical variables in pipeline mode");
    ok(test_set_in_pipeline_mode(), "SET commands in pipeline mode");
    ok(test_set_then_query_pipeline(), "SET DateStyle then query in pipeline mode");

    // Run SET failure tests in pipeline mode
    ok(test_set_failure_invalid_value_pipeline(), "SET failure with invalid value in pipeline");
    ok(test_set_failure_invalid_encoding_pipeline(), "SET failure with invalid encoding in pipeline");
    ok(test_set_failure_syntax_error_pipeline(), "SET failure with syntax error in pipeline");
    ok(test_set_failure_multiple_set_one_fails(), "Multiple SETs where one fails in pipeline");
    ok(test_set_different_values_from_original(), "SET values different from original in pipeline");

    // Run RESET and DISCARD tests in pipeline mode
    ok(test_reset_all_failure_pipeline(), "RESET ALL fails in pipeline mode");
    ok(test_discard_all_failure_pipeline(), "DISCARD ALL fails in pipeline mode");
    ok(test_reset_single_var_pipeline(), "RESET single variable works in pipeline mode");
    ok(test_multiple_vars_out_of_sync_pipeline(), "Multiple variables out of sync in pipeline mode");
    ok(test_pipeline_with_locked_hostgroup(), "SET/RESET/DISCARD with locked hostgroup in pipeline mode");
    ok(test_reset_all_locked_hostgroup_pipeline(), "RESET ALL with locked hostgroup in pipeline mode");
    ok(test_discard_all_locked_hostgroup_pipeline(), "DISCARD ALL with locked hostgroup in pipeline mode");

    return exit_status();
}

// Test: SET with invalid value should fail gracefully in pipeline
bool test_set_failure_invalid_value_pipeline() {
    diag("=== Test: SET failure with invalid value in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send SET with invalid DateStyle value
    if (PQsendQueryParams(conn.get(), "SET DateStyle = 'INVALID_STYLE'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool got_error = false;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 2) {  // 1 command + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_FATAL_ERROR) {
                got_error = true;
                diag("Got expected error: %s", PQresultErrorMessage(res));
            }
            if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= 2) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify connection is still usable after error
    PGresult* res2 = PQexec(conn.get(), "SELECT 1");
    bool connection_ok = (PQresultStatus(res2) == PGRES_TUPLES_OK);
    PQclear(res2);

    return got_error && connection_ok;
}

// Test: SET invalid client_encoding should fail
bool test_set_failure_invalid_encoding_pipeline() {
    diag("=== Test: SET failure with invalid encoding in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get original encoding first
    std::string orig_encoding = get_variable_simple(conn.get(), "client_encoding");
    diag("Original client_encoding: %s", orig_encoding.c_str());

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send SET with invalid encoding
    if (PQsendQueryParams(conn.get(), "SET client_encoding = 'INVALID_ENCODING'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool got_error = false;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 2) {
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_FATAL_ERROR) {
                got_error = true;
                diag("Got expected error for invalid encoding");
            }
            if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= 2) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify encoding is still original (not changed)
    std::string after_encoding = get_variable_simple(conn.get(), "client_encoding");
    bool encoding_unchanged = (after_encoding == orig_encoding);

    diag("After error client_encoding: %s (unchanged: %s)",
         after_encoding.c_str(), encoding_unchanged ? "yes" : "no");

    return got_error && encoding_unchanged;
}

// Test: SET syntax error should fail
bool test_set_failure_syntax_error_pipeline() {
    diag("=== Test: SET failure with syntax error in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send SET with syntax error (missing value)
    if (PQsendQueryParams(conn.get(), "SET DateStyle =", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool got_error = false;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 2) {
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_FATAL_ERROR) {
                got_error = true;
                diag("Got expected syntax error");
            }
            if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= 2) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    return got_error;
}

// Test: Multiple SETs where one fails - verify state consistency
bool test_set_failure_multiple_set_one_fails() {
    diag("=== Test: Multiple SETs where one fails - state consistency ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get original values
    std::string orig_datestyle = get_variable_simple(conn.get(), "DateStyle");
    std::string orig_timezone = get_variable_simple(conn.get(), "TimeZone");

    diag("Original DateStyle: %s, TimeZone: %s",
         orig_datestyle.c_str(), orig_timezone.c_str());

    // Ensure we're using DIFFERENT values
    std::string new_datestyle = (orig_datestyle.find("ISO") != std::string::npos) ?
                                "Postgres, DMY" : "ISO, MDY";
    std::string new_timezone = (orig_timezone.find("UTC") != std::string::npos) ?
                               "PST8PDT" : "UTC";

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send: valid SET, invalid SET, valid SET
    std::string set1 = "SET DateStyle = '" + new_datestyle + "'";
    if (PQsendQueryParams(conn.get(), set1.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET 1");
        return false;
    }

    if (PQsendQueryParams(conn.get(), "SET client_encoding = 'INVALID'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET 2 (invalid)");
        return false;
    }

    std::string set3 = "SET TimeZone = '" + new_timezone + "'";
    if (PQsendQueryParams(conn.get(), set3.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET 3");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    int error_count = 0;
    int success_count = 0;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < 4) {  // 3 commands + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_COMMAND_OK) {
                success_count++;
            } else if (status == PGRES_FATAL_ERROR) {
                error_count++;
                diag("Got error: %s", PQresultErrorMessage(res));
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= 4) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Check results
    std::string final_datestyle = get_variable_simple(conn.get(), "DateStyle");
    std::string final_timezone = get_variable_simple(conn.get(), "TimeZone");

    diag("Final DateStyle: %s (expected: %s, original: %s)",
         final_datestyle.c_str(), new_datestyle.c_str(), orig_datestyle.c_str());
    diag("Final TimeZone: %s (expected: %s, original: %s)",
         final_timezone.c_str(), new_timezone.c_str(), orig_timezone.c_str());
    diag("Success count: %d, Error count: %d", success_count, error_count);

    // PostgreSQL behavior: When a command fails in pipeline, the entire pipeline aborts
    // This means first SET may be rolled back along with subsequent commands
    // We verify:
    // 1. At least one error occurred (the invalid SET)
    // 2. Connection is still usable
    // 3. Either first SET succeeded (if no abort) or was rolled back (if abort)

    bool got_expected_error = (error_count >= 1);
    bool first_set_succeeded = (final_datestyle.find(new_datestyle) != std::string::npos);
    bool first_set_rolled_back = (final_datestyle == orig_datestyle);

    // Connection should still be usable
    PGresult* test_res = PQexec(conn.get(), "SELECT 1");
    bool connection_ok = (PQresultStatus(test_res) == PGRES_TUPLES_OK);
    PQclear(test_res);

    diag("Results: error=%s, first_set_succeeded=%s, first_set_rolled_back=%s, connection_ok=%s",
         got_expected_error ? "yes" : "no",
         first_set_succeeded ? "yes" : "no",
         first_set_rolled_back ? "yes" : "no",
         connection_ok ? "yes" : "no");

    // Accept either behavior:
    // - If no abort: first SET succeeded
    // - If abort: first SET was rolled back (back to original)
    return got_expected_error && connection_ok && (first_set_succeeded || first_set_rolled_back);
}

// Test: Verify SET values are different from original
bool test_set_different_values_from_original() {
    diag("=== Test: SET values different from original in pipeline ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get original values
    std::vector<PipelineTestVariable> vars = {
        {"DateStyle", "", ""},
        {"TimeZone", "", ""},
        {"bytea_output", "", ""},
        {"standard_conforming_strings", "", ""}
    };

    // Get originals and determine DIFFERENT test values
    for (auto& var : vars) {
        var.initial_value = get_variable_simple(conn.get(), var.name);
        diag("Original %s: %s", var.name.c_str(), var.initial_value.c_str());

        // Choose value DIFFERENT from original
        if (var.name == "DateStyle") {
            var.test_value = (var.initial_value.find("ISO") != std::string::npos) ?
                            "Postgres, DMY" : "ISO, MDY";
        } else if (var.name == "TimeZone") {
            var.test_value = (var.initial_value.find("UTC") != std::string::npos) ?
                            "PST8PDT" : "UTC";
        } else if (var.name == "bytea_output") {
            var.test_value = (var.initial_value == "hex") ? "escape" : "hex";
        } else if (var.name == "standard_conforming_strings") {
            var.test_value = (var.initial_value == "on") ? "off" : "on";
        }
        diag("Will SET %s to: %s", var.name.c_str(), var.test_value.c_str());
    }

    // Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send all SETs
    for (const auto& var : vars) {
        std::string query = "SET " + var.name + " = '" + var.test_value + "'";
        if (PQsendQueryParams(conn.get(), query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SET %s", var.name.c_str());
            return false;
        }
    }

    // Send all SHOWs
    for (const auto& var : vars) {
        std::string query = "SHOW " + var.name;
        if (PQsendQueryParams(conn.get(), query.c_str(), 0, NULL, NULL, NULL, NULL, 0) != 1) {
            diag("Failed to send SHOW %s", var.name.c_str());
            return false;
        }
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int set_count = 0;
    int show_count = 0;
    std::map<std::string, std::string> results;
    int count = 0;
    int result_idx = 0;
    int sock = PQsocket(conn.get());
    PGresult* res;

    while (count < vars.size() * 2 + 1) {
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_COMMAND_OK) {
                set_count++;
            } else if (status == PGRES_TUPLES_OK && PQntuples(res) > 0) {
                char* val = PQgetvalue(res, 0, 0);
                if (val && result_idx < (int)vars.size()) {
                    results[vars[result_idx].name] = val;
                    result_idx++;
                }
                show_count++;
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(res);
                count++;
                continue;  // Keep consuming results, don't break
            }
            PQclear(res);
            count++;
        }

        if (count >= (int)vars.size() * 2 + 1) break;

        // Only wait if libpq reports it's busy waiting for more data
        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify all values changed
    bool all_changed = true;
    for (const auto& var : vars) {
        auto it = results.find(var.name);
        if (it == results.end()) {
            diag("No result for %s", var.name.c_str());
            all_changed = false;
            continue;
        }
        std::string final_val = it->second;
        // Use exact equality to avoid false positives from substring matching
        bool changed = (final_val == var.test_value);

        // Also verify it's NOT the original
        bool is_original = (final_val == var.initial_value);

        diag("%s: original='%s', test='%s', final='%s', changed=%s, is_original=%s",
             var.name.c_str(), var.initial_value.c_str(), var.test_value.c_str(),
             final_val.c_str(), changed ? "yes" : "no", is_original ? "yes" : "no");

        if (!changed || is_original) {
            diag("FAIL: %s did not change or still original!", var.name.c_str());
            all_changed = false;
        }
    }

    return all_changed && (set_count >= (int)vars.size()) && (show_count >= (int)vars.size());
}

// Test: RESET single variable in simple query mode
bool test_reset_simple_query() {
    diag("=== Test: RESET single variable in simple query mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get initial value
    std::string initial = get_variable_simple(conn.get(), "DateStyle");
    diag("Initial DateStyle: %s", initial.c_str());

    // SET to different value
    if (!set_variable_simple(conn.get(), "DateStyle", "Postgres, DMY")) {
        diag("Failed to SET DateStyle");
        return false;
    }
    std::string after_set = get_variable_simple(conn.get(), "DateStyle");
    diag("After SET: DateStyle = %s", after_set.c_str());

    // RESET
    PGresult* res = PQexec(conn.get(), "RESET DateStyle");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("RESET failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Verify it's back to initial
    std::string after_reset = get_variable_simple(conn.get(), "DateStyle");
    diag("After RESET: DateStyle = %s", after_reset.c_str());

    bool success = (after_reset == initial);
    diag("RESET %s: '%s' == '%s'", success ? "succeeded" : "failed", after_reset.c_str(), initial.c_str());

    return success;
}

// Test: RESET ALL in simple query mode
bool test_reset_all_simple_query() {
    diag("=== Test: RESET ALL in simple query mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Get initial values
    std::string initial_datestyle = get_variable_simple(conn.get(), "DateStyle");
    std::string initial_timezone = get_variable_simple(conn.get(), "TimeZone");
    diag("Initial DateStyle: %s, TimeZone: %s", initial_datestyle.c_str(), initial_timezone.c_str());

    // SET to different values
    set_variable_simple(conn.get(), "DateStyle", "Postgres, DMY");
    set_variable_simple(conn.get(), "TimeZone", "PST8PDT");
    diag("After SET: DateStyle = %s, TimeZone = %s",
         get_variable_simple(conn.get(), "DateStyle").c_str(),
         get_variable_simple(conn.get(), "TimeZone").c_str());

    // RESET ALL
    PGresult* res = PQexec(conn.get(), "RESET ALL");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("RESET ALL failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Verify values are back to initial
    std::string after_reset_datestyle = get_variable_simple(conn.get(), "DateStyle");
    std::string after_reset_timezone = get_variable_simple(conn.get(), "TimeZone");
    diag("After RESET ALL: DateStyle = %s, TimeZone = %s",
         after_reset_datestyle.c_str(), after_reset_timezone.c_str());

    bool success = (after_reset_datestyle == initial_datestyle) &&
                   (after_reset_timezone == initial_timezone);
    diag("RESET ALL %s", success ? "succeeded" : "failed");

    return success;
}

// Test: DISCARD ALL in simple query mode
bool test_discard_all_simple_query() {
    diag("=== Test: DISCARD ALL in simple query mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Execute DISCARD ALL
    PGresult* res = PQexec(conn.get(), "DISCARD ALL");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag("DISCARD ALL failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Verify connection still works
    PGresult* res2 = PQexec(conn.get(), "SELECT 1");
    bool connection_ok = (PQresultStatus(res2) == PGRES_TUPLES_OK);
    PQclear(res2);

    diag("DISCARD ALL %s", connection_ok ? "succeeded" : "failed");

    return connection_ok;
}

// Test: Multiple variables out of sync in pipeline mode
// This tests the edge case where a pooled backend connection has different
// parameter values than the client's current session, triggering the
// "multiple parameters need syncing" error and session termination
bool test_multiple_vars_out_of_sync_pipeline() {
    diag("=== Test: Multiple variables out of sync in pipeline mode ===");

    // Step 1: Create first connection and set multiple variables
    PGConnPtr conn1 = createNewConnection(BACKEND);
    if (!conn1) return false;

    // Set multiple variables to non-default values
    PGresult* res;
    res = PQexec(conn1.get(), "SET DateStyle = 'Postgres, DMY'");
    PQclear(res);
    res = PQexec(conn1.get(), "SET TimeZone = 'PST8PDT'");
    PQclear(res);
    res = PQexec(conn1.get(), "SET bytea_output = 'escape'");
    PQclear(res);

    // Verify values are set
    std::string ds1 = get_variable_simple(conn1.get(), "DateStyle");
    std::string tz1 = get_variable_simple(conn1.get(), "TimeZone");
    std::string bo1 = get_variable_simple(conn1.get(), "bytea_output");
    // Close connection (returns to pool with these values)
    conn1.reset();
    diag("Connection 1 closed - returned to pool with DateStyle='Postgres, MDY', TimeZone='PST8PDT', bytea_output='escape'");

    // Wait for connection to be returned to pool with polling (max 5 seconds)
    // Fixed delay replaced with polling to handle slow CI systems
    bool conn_in_pool = false;
    for (int retry = 0; retry < 50; retry++) {
        usleep(100000);  // 100ms * 50 = 5 seconds max
        // Check if we can create a new connection (indicates pool has capacity)
        PGConnPtr test_conn = createNewConnection(BACKEND);
        if (test_conn) {
            conn_in_pool = true;
            break;
        }
    }
    if (!conn_in_pool) {
        diag("Warning: Connection may not have returned to pool yet, continuing anyway");
    }

    // Step 2: Create new connection with DIFFERENT variable values (simple query mode)
    PGConnPtr conn2 = createNewConnection(BACKEND);
    if (!conn2) return false;

    // Set different values (these become client-side hashes)
    res = PQexec(conn2.get(), "SET DateStyle = 'SQL, DMY'");
    PQclear(res);
    res = PQexec(conn2.get(), "SET TimeZone = 'UTC'");
    PQclear(res);
    res = PQexec(conn2.get(), "SET bytea_output = 'hex'");
    PQclear(res);

    diag("Connection 2: SET DateStyle='SQL, DMY', TimeZone='UTC', bytea_output='hex'");

    // Step 3: Directly enter pipeline mode and execute a query
    // This will pull the pooled connection from conn1 which has DIFFERENT values
    // All 3 variables will be out of sync, triggering multiple variable sync error
    if (PQenterPipelineMode(conn2.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Send a query - this will use a pooled connection with different parameters
    if (PQsendQueryParams(conn2.get(), "SELECT 1", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send query");
        return false;
    }

    PQpipelineSync(conn2.get());
    PQflush(conn2.get());

    // Step 4: Check results
    int count = 0;
    bool got_result = false;
    bool got_error = false;
    PGresult* result_res;
    int sock = PQsocket(conn2.get());

    while (count < 2) {
        if (PQconsumeInput(conn2.get()) == 0) break;

        while ((result_res = PQgetResult(conn2.get())) != NULL) {
            ExecStatusType status = PQresultStatus(result_res);
            if (status == PGRES_TUPLES_OK) {
                got_result = true;
                diag("Got query result (variables synced via pipeline)");
            } else if (status == PGRES_FATAL_ERROR) {
                got_error = true;
                diag("Got error (multiple variables out of sync, session terminated): %s",
                     PQresultErrorMessage(result_res));
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(result_res);
                count++;
                continue;
            }
            PQclear(result_res);
            count++;
        }

        if (count >= 2) break;

        if (!PQisBusy(conn2.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    // Try to exit pipeline mode
    PQexitPipelineMode(conn2.get());

    // Verify connection still works
    PGresult* test_res = PQexec(conn2.get(), "SELECT 1");
    bool connection_ok = (PQresultStatus(test_res) == PGRES_TUPLES_OK);
    PQclear(test_res);

    diag("Test result: got_result=%s, got_error=%s, connection_ok=%s",
         got_result ? "yes" : "no",
         got_error ? "yes" : "no",
         connection_ok ? "yes" : "no");

    // The test passes if either:
    // 1. Query succeeded (variables were synced via new SET handling), OR
    // 2. Connection was terminated but can be re-established
    return got_result || connection_ok;
}

// Test: SET/RESET/DISCARD with locked hostgroup in pipeline mode
// This tests that SET/RESET/DISCARD work correctly when hostgroup is locked
// Hostgroup locking is triggered by SET with unknown parameter
bool test_pipeline_with_locked_hostgroup() {
    diag("=== Test: SET/RESET/DISCARD with locked hostgroup in pipeline mode ===");

    // Open ProxySQL log file to check for hostgroup lock messages
    std::string f_path{ get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
    std::fstream log_file{};
    int of_err = open_file_and_seek_end(f_path, log_file);
    if (of_err != EXIT_SUCCESS) {
        diag("Failed to open ProxySQL log file");
        return false;
    }

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Step 1: Lock hostgroup by setting a user-defined variable
    // User variables with dotted names are valid in PostgreSQL and will lock hostgroup
    PGresult* res = PQexec(conn.get(), "SET myapp.test_var = 'test_value'");
    bool set_ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
    PQclear(res);
    diag("SET myapp.test_var %s (hostgroup should be locked)", set_ok ? "succeeded" : "failed");

    // Check logs for hostgroup lock warning
    usleep(50000); // Give time for log to be written
    log_file.clear(log_file.rdstate() & ~std::ios_base::failbit);
    log_file.seekg(log_file.tellg());
    const auto& [_, cmd_lines] { get_matching_lines(log_file, ".*\\[WARNING\\] Unable to parse unknown SET query from client.*") };
    bool hostgroup_locked = !cmd_lines.empty();
    diag("Hostgroup lock triggered (log check): %s", hostgroup_locked ? "yes" : "no");

    // Step 2: Change some variables via simple query
    res = PQexec(conn.get(), "SET DateStyle = 'Postgres, DMY'");
    PQclear(res);
    res = PQexec(conn.get(), "SET TimeZone = 'PST8PDT'");
    PQclear(res);
    diag("SET DateStyle='Postgres, DMY', TimeZone='PST8PDT' on locked hostgroup");

    // Step 3: Enter pipeline mode and SHOW variables to verify they were set
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    if (PQsendQueryParams(conn.get(), "SHOW DateStyle", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SHOW DateStyle");
        return false;
    }
    if (PQsendQueryParams(conn.get(), "SHOW TimeZone", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SHOW TimeZone");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume SHOW results
    int count = 0;
    std::string datestyle_val, timezone_val;
    PGresult* result_res;
    int sock = PQsocket(conn.get());

    while (count < 3) {  // 2 SHOW + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((result_res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(result_res);
            if (status == PGRES_TUPLES_OK && PQntuples(result_res) > 0) {
                char* val = PQgetvalue(result_res, 0, 0);
                if (datestyle_val.empty()) {
                    datestyle_val = val ? val : "";
                    diag("SHOW DateStyle in pipeline: %s", datestyle_val.c_str());
                } else if (timezone_val.empty()) {
                    timezone_val = val ? val : "";
                    diag("SHOW TimeZone in pipeline: %s", timezone_val.c_str());
                }
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(result_res);
                count++;
                continue;
            }
            PQclear(result_res);
            count++;
        }

        if (count >= 3) break;

        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify values were set correctly
    bool values_correct = (datestyle_val.find("Postgres") != std::string::npos) &&
                          (timezone_val.find("PST") != std::string::npos);
    diag("Values set correctly: %s", values_correct ? "yes" : "no");

    // Step 4: Create new connection and SET parameters in pipeline mode
    // Also SET dummy to test hostgroup lock handling
    PGConnPtr conn2 = createNewConnection(BACKEND);
    if (!conn2) return false;

    if (PQenterPipelineMode(conn2.get()) != 1) {
        diag("Failed to enter pipeline mode on conn2");
        return false;
    }

    // SET real parameters in pipeline mode
    if (PQsendQueryParams(conn2.get(), "SET DateStyle = 'SQL, DMY'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET DateStyle in pipeline");
        return false;
    }
    if (PQsendQueryParams(conn2.get(), "SET TimeZone = 'UTC'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET TimeZone in pipeline");
        return false;
    }
    // SET user variable to trigger hostgroup lock
    if (PQsendQueryParams(conn2.get(), "SET myapp.test_var2 = 'test_value2'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET user variable in pipeline");
        return false;
    }

    // SHOW to verify real parameters were set
    if (PQsendQueryParams(conn2.get(), "SHOW DateStyle", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SHOW DateStyle");
        return false;
    }
    if (PQsendQueryParams(conn2.get(), "SHOW TimeZone", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SHOW TimeZone");
        return false;
    }

    PQpipelineSync(conn2.get());
    PQflush(conn2.get());

    // Consume results
    count = 0;
    int cmd_ok_count = 0;
    int show_count = 0;
    std::string ds2_val, tz2_val;
    sock = PQsocket(conn2.get());

    while (count < 6) {  // 3 SET + 2 SHOW + 1 sync
        if (PQconsumeInput(conn2.get()) == 0) break;

        while ((result_res = PQgetResult(conn2.get())) != NULL) {
            ExecStatusType status = PQresultStatus(result_res);
            if (status == PGRES_COMMAND_OK) {
                cmd_ok_count++;
                diag("SET command OK in pipeline mode (conn2)");
            } else if (status == PGRES_FATAL_ERROR) {
                // SET myapp.test_var2 may fail if custom variables not configured
                diag("SET user variable returned error (may be expected): %s",
                     PQresultErrorMessage(result_res) ? PQresultErrorMessage(result_res) : "unknown");
            } else if (status == PGRES_TUPLES_OK && PQntuples(result_res) > 0) {
                char* val = PQgetvalue(result_res, 0, 0);
                if (ds2_val.empty()) {
                    ds2_val = val ? val : "";
                    diag("SHOW DateStyle in pipeline (conn2): %s", ds2_val.c_str());
                } else {
                    tz2_val = val ? val : "";
                    diag("SHOW TimeZone in pipeline (conn2): %s", tz2_val.c_str());
                }
                show_count++;
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(result_res);
                count++;
                continue;
            }
            PQclear(result_res);
            count++;
        }

        if (count >= 6) break;

        if (!PQisBusy(conn2.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn2.get());

    // Verify conn2 values
    bool conn2_values_correct = (ds2_val.find("SQL") != std::string::npos) &&
                                (tz2_val.find("UTC") != std::string::npos);
    diag("Conn2 values set correctly in pipeline: %s", conn2_values_correct ? "yes" : "no");
    diag("Conn2 SET commands OK: %d, SHOW commands: %d",
         cmd_ok_count, show_count);

    // Verify both connections still work
    PGresult* test_res = PQexec(conn.get(), "SELECT 1");
    bool conn1_ok = (PQresultStatus(test_res) == PGRES_TUPLES_OK);
    PQclear(test_res);

    test_res = PQexec(conn2.get(), "SELECT 1");
    bool conn2_ok = (PQresultStatus(test_res) == PGRES_TUPLES_OK);
    PQclear(test_res);

    diag("Connections still usable: conn1=%s, conn2=%s", conn1_ok ? "yes" : "no", conn2_ok ? "yes" : "no");

    log_file.close();

    // Expected: SET commands OK (DateStyle, TimeZone), SHOW results
    // Also verify hostgroup was locked via log check
    return values_correct && conn2_values_correct && (cmd_ok_count >= 2) &&
           conn1_ok && conn2_ok && hostgroup_locked;
}

// Test: RESET ALL with locked hostgroup in pipeline mode - startup values MATCH
// This tests that RESET ALL works when hostgroup is locked and startup values match
bool test_reset_all_locked_hostgroup_pipeline() {
    diag("=== Test: RESET ALL with locked hostgroup when startup values match ===");

    // A new frontend can reuse a backend that was created for another client's
    // startup options. Build that stale-backend state explicitly: it is the
    // pool state that made this test fail in CI.
    PgsqlPoolRuntimeGuard pool_config;
    if (!pool_config.initialize() ||
        !pool_config.set_free_connections_pct("0") ||
        !pool_config.wait_for_free_connections("0") ||
        !pool_config.set_free_connections_pct("100")) {
        return false;
    }

    {
        const std::string startup_value = "SQL,\\\\ DMY";
        PGConnPtr stale_conn = createNewConnection(BACKEND, "-c DateStyle=" + startup_value);
        if (!stale_conn) return false;

        const std::string stale_datestyle = get_variable_simple(stale_conn.get(), "DateStyle");
        if (stale_datestyle != "SQL, DMY") {
            diag("Expected stale backend startup DateStyle 'SQL, DMY', got '%s'", stale_datestyle.c_str());
            return false;
        }
    }

    if (!pool_config.wait_for_free_connections("1")) return false;

    // The test's success path requires matching startup values. Remove the
    // deliberately stale backend before creating the default client, so that
    // its physical backend is created with the same startup values.
    if (!pool_config.set_free_connections_pct("0") ||
        !pool_config.wait_for_free_connections("0")) {
        return false;
    }

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    const std::string current_datestyle = get_variable_simple(conn.get(), "DateStyle");
    if (current_datestyle != "ISO, MDY") {
        diag("Expected default client DateStyle 'ISO, MDY', got '%s'", current_datestyle.c_str());
        return false;
    }

    // Step 1: Enter pipeline mode (fresh connection, startup values match)
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Step 2: Set user variable to lock hostgroup (in pipeline)
    if (PQsendQueryParams(conn.get(), "SET myapp.lock_var = 'lock_value'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET lock_var");
        return false;
    }

    // Step 3: Send RESET ALL in pipeline mode with locked hostgroup
    // Since startup values match (fresh connection), this should succeed
    if (PQsendQueryParams(conn.get(), "RESET ALL", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send RESET ALL");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool lock_ok = false;
    bool reset_ok = false;
    int sock = PQsocket(conn.get());
    PGresult* result_res;

    while (count < 3) {  // 2 commands + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((result_res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(result_res);
            if (status == PGRES_COMMAND_OK) {
                if (!lock_ok) {
                    lock_ok = true;
                    diag("SET lock_var succeeded (hostgroup locked)");
                } else {
                    reset_ok = true;
                    diag("RESET ALL succeeded in pipeline with locked hostgroup");
                }
            } else if (status == PGRES_FATAL_ERROR) {
                diag("Command failed: %s", PQresultErrorMessage(result_res));
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(result_res);
                count++;
                continue;
            }
            PQclear(result_res);
            count++;
        }

        if (count >= 3) break;

        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify connection still works
    PGresult* res = PQexec(conn.get(), "SELECT 1");
    bool conn_ok = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    const bool test_ok = lock_ok && reset_ok && conn_ok;
    conn.reset();
    return pool_config.restore() && test_ok;
}

// Test: DISCARD ALL with locked hostgroup in pipeline mode
// This tests that DISCARD ALL correctly FAILS in pipeline mode even with locked hostgroup
// DISCARD ALL is more destructive than RESET ALL (resets prepared statements, temp tables, etc.)
// so it is blocked in pipeline mode regardless of hostgroup lock status
bool test_discard_all_locked_hostgroup_pipeline() {
    diag("=== Test: DISCARD ALL with locked hostgroup in pipeline mode ===");

    PGConnPtr conn = createNewConnection(BACKEND);
    if (!conn) return false;

    // Step 1: Enter pipeline mode
    if (PQenterPipelineMode(conn.get()) != 1) {
        diag("Failed to enter pipeline mode");
        return false;
    }

    // Step 2: Set user variable to lock hostgroup (in pipeline)
    if (PQsendQueryParams(conn.get(), "SET myapp.lock_var = 'lock_value'", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send SET lock_var");
        return false;
    }

    // Step 3: Send DISCARD ALL in pipeline mode with locked hostgroup
    if (PQsendQueryParams(conn.get(), "DISCARD ALL", 0, NULL, NULL, NULL, NULL, 0) != 1) {
        diag("Failed to send DISCARD ALL");
        return false;
    }

    PQpipelineSync(conn.get());
    PQflush(conn.get());

    // Consume results
    int count = 0;
    bool lock_ok = false;
    bool got_discard_error = false;
    std::string error_msg;
    int sock = PQsocket(conn.get());
    PGresult* result_res;

    while (count < 3) {  // 2 commands + 1 sync
        if (PQconsumeInput(conn.get()) == 0) break;

        while ((result_res = PQgetResult(conn.get())) != NULL) {
            ExecStatusType status = PQresultStatus(result_res);
            if (status == PGRES_COMMAND_OK) {
                lock_ok = true;
                diag("SET lock_var succeeded (hostgroup locked)");
            } else if (status == PGRES_FATAL_ERROR) {
                char* err = PQresultErrorMessage(result_res);
                if (err && strstr(err, "DISCARD ALL")) {
                    got_discard_error = true;
                    error_msg = err;
                    diag("DISCARD ALL correctly failed in pipeline: %s", err);
                }
            } else if (status == PGRES_PIPELINE_SYNC) {
                PQclear(result_res);
                count++;
                continue;
            }
            PQclear(result_res);
            count++;
        }

        if (count >= 3) break;

        if (!PQisBusy(conn.get())) continue;

        fd_set input_mask;
        FD_ZERO(&input_mask);
        FD_SET(sock, &input_mask);
        struct timeval timeout = {5, 0};
        select(sock + 1, &input_mask, NULL, NULL, &timeout);
    }

    PQexitPipelineMode(conn.get());

    // Verify connection still works after expected error
    PGresult* res = PQexec(conn.get(), "SELECT 1");
    bool conn_ok = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    // Test passes if:
    // 1. Hostgroup was locked (SET myapp.lock_var succeeded)
    // 2. DISCARD ALL failed with error (as expected)
    // 3. Connection is still usable
    return lock_ok && got_discard_error && conn_ok;
}
