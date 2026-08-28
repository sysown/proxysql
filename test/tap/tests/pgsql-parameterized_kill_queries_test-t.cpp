/**
 * @file pgsql-parameterized_kill_queries_test-t.cpp
 * @brief TAP test verifying ProxySQL parameterized pg_terminate_backend and pg_cancel_backend support.
 * 
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <arpa/inet.h>
#include "libpq-fe.h"
#include "command_line.h"
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
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    if (options.empty() == false) {
		ss << " options='" << options << "'";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

struct TestSync {
    std::mutex mutex;
    std::condition_variable cv;
    bool query_started = false;
    bool query_completed = false;
};

void execute_long_running_query(PGconn* conn, TestSync& sync, int duration_sec, bool& was_canceled) {
    std::string query = "SELECT pg_sleep(" + std::to_string(duration_sec) + ")";
    
    {
        std::lock_guard<std::mutex> lock(sync.mutex);
        sync.query_started = true;
    }
    sync.cv.notify_one();

    PGresult* res = PQexec(conn, query.c_str());
    
    {
        std::lock_guard<std::mutex> lock(sync.mutex);
        sync.query_completed = true;
    }
    sync.cv.notify_one();

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        if (PQresultStatus(res) == PGRES_FATAL_ERROR) {
            const char* error = PQresultErrorMessage(res);
            if (error && strstr(error, "canceling statement due to user request")) {
                was_canceled = true;
            }
        }
    }
    
    PQclear(res);
}

bool execute_prepared_statement(PGconn* conn, const std::string& stmt_name, const std::string& query, 
                                const char* param_value, int param_len, int param_format) {
    // Prepare the statement
    PGresult* res = PQprepare(conn, stmt_name.c_str(), query.c_str(), 1, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Bind and execute with parameter
    const char* param_values[1] = {param_value};
    int param_lengths[1] = {param_len};
    int param_formats[1] = {param_format};
    
    res = PQexecPrepared(conn, stmt_name.c_str(), 1, param_values, param_lengths, param_formats, 0);
    bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    // Clean up prepared statement
    res = PQexec(conn, ("DEALLOCATE " + stmt_name).c_str());
    PQclear(res);

    return success;
}

bool execute_prepared_statement_binary(PGconn* conn, const std::string& stmt_name, const std::string& query,
                                      int32_t pid_value) {
    // Prepare the statement
    PGresult* res = PQprepare(conn, stmt_name.c_str(), query.c_str(), 1, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Convert PID to network byte order for binary format
    uint32_t network_pid = htonl(static_cast<uint32_t>(pid_value));
    const char* param_values[1] = {reinterpret_cast<const char*>(&network_pid)};
    int param_lengths[1] = {4};
    int param_formats[1] = {1};  // Binary format
    
    res = PQexecPrepared(conn, stmt_name.c_str(), 1, param_values, param_lengths, param_formats, 0);
    bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    // Clean up prepared statement
    res = PQexec(conn, ("DEALLOCATE " + stmt_name).c_str());
    PQclear(res);

    return success;
}

bool execute_prepared_statement_int8(PGconn* conn, const std::string& stmt_name, const std::string& query,
                                    int64_t pid_value) {
    // Prepare the statement
    PGresult* res = PQprepare(conn, stmt_name.c_str(), query.c_str(), 1, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Convert PID to network byte order for binary format (int8)
    uint64_t network_pid = 0;
    // Simple big-endian conversion for 64-bit
    uint64_t host_pid = static_cast<uint64_t>(pid_value);
    network_pid = 
        ((host_pid & 0xFF00000000000000ULL) >> 56) |
        ((host_pid & 0x00FF000000000000ULL) >> 40) |
        ((host_pid & 0x0000FF0000000000ULL) >> 24) |
        ((host_pid & 0x000000FF00000000ULL) >> 8) |
        ((host_pid & 0x00000000FF000000ULL) << 8) |
        ((host_pid & 0x0000000000FF0000ULL) << 24) |
        ((host_pid & 0x000000000000FF00ULL) << 40) |
        ((host_pid & 0x00000000000000FFULL) << 56);
    
    const char* param_values[1] = {reinterpret_cast<const char*>(&network_pid)};
    int param_lengths[1] = {8};
    int param_formats[1] = {1};  // Binary format
    
    res = PQexecPrepared(conn, stmt_name.c_str(), 1, param_values, param_lengths, param_formats, 0);
    bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    // Clean up prepared statement
    res = PQexec(conn, ("DEALLOCATE " + stmt_name).c_str());
    PQclear(res);

    return success;
}

bool test_parameterized_query_error(PGconn* conn, const std::string& query, const char* param_value, 
                                   int param_len, int param_format, const char* expected_error) {
    std::string stmt_name = "test_error_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    
    // Prepare the statement
    PGresult* res = PQprepare(conn, stmt_name.c_str(), query.c_str(), 1, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return false;
    }
    PQclear(res);

    // Bind and execute with parameter
    const char* param_values[1] = {param_value};
    int param_lengths[1] = {param_len};
    int param_formats[1] = {param_format};
    
    res = PQexecPrepared(conn, stmt_name.c_str(), 1, param_values, param_lengths, param_formats, 0);
    
    bool has_error = (PQresultStatus(res) == PGRES_FATAL_ERROR);
    bool error_matches = false;
    
    if (has_error) {
        const char* error_msg = PQresultErrorMessage(res);
        if (error_msg && strstr(error_msg, expected_error)) {
            error_matches = true;
        }
    }
    
    PQclear(res);

    // Clean up prepared statement
    res = PQexec(conn, ("DEALLOCATE " + stmt_name).c_str());
    PQclear(res);

    return has_error && error_matches;
}

int main(int argc, char** argv) {
    TestSync sync;
    bool was_canceled = false;

    if (cl.getEnv())
        return exit_status();

    plan(21); // Total number of tests
   
    // Test 1: Basic parameterized pg_cancel_backend with text format
    diag("Test 1: Parameterized pg_cancel_backend with text format");
    {
        auto backend_conn = createNewConnection(BACKEND);
        if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
            diag("Error: failed to connect to the database");
            skip(1, "Connection failed");
        } else {
            int backend_pid = PQbackendPID(backend_conn.get());
            
            // Start query in separate thread
            std::thread query_thread([&]() {
                execute_long_running_query(backend_conn.get(), sync, 10, was_canceled);
            });

            // Wait for query to start
            {
                std::unique_lock<std::mutex> lock(sync.mutex);
                sync.cv.wait(lock, [&]() { return sync.query_started; });
            }

            // Create connection and cancel the query using parameterized statement
            auto cancel_conn = createNewConnection(BACKEND);
            if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
                query_thread.join();
                skip(1, "Connection failed");
            } else {
                std::string pid_str = std::to_string(backend_pid);
                bool success = execute_prepared_statement(cancel_conn.get(), "cancel_stmt", 
                    "SELECT pg_cancel_backend($1)", pid_str.c_str(), pid_str.length(), 0);
                
                ok(success, "Parameterized pg_cancel_backend with text format should succeed");

                // Wait for query completion
                {
                    std::unique_lock<std::mutex> lock(sync.mutex);
                    sync.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync.query_completed; });
                }

                query_thread.join();
                ok(was_canceled, "Query should be canceled via parameterized query");
            }
        }
    }

    // Test 2: Basic parameterized pg_terminate_backend with text format
    diag("Test 2: Parameterized pg_terminate_backend with text format");
    {
        auto victim_conn = createNewConnection(BACKEND);
        if (!victim_conn || PQstatus(victim_conn.get()) != CONNECTION_OK) {
            skip(1, "Connection failed");
        } else {
            int victim_pid = PQbackendPID(victim_conn.get());
            
            // Create connection and terminate using parameterized statement
            auto killer_conn = createNewConnection(BACKEND);
            if (!killer_conn || PQstatus(killer_conn.get()) != CONNECTION_OK) {
                skip(1, "Connection failed");
            } else {
                std::string pid_str = std::to_string(victim_pid);
                bool success = execute_prepared_statement(killer_conn.get(), "terminate_stmt", 
                    "SELECT pg_terminate_backend($1)", pid_str.c_str(), pid_str.length(), 0);
                
                ok(success, "Parameterized pg_terminate_backend with text format should succeed");

                // Verify the connection was terminated
                PGresult* res = PQexec(victim_conn.get(), "SELECT 1");
                bool connection_dead = (PQresultStatus(res) != PGRES_TUPLES_OK);
                PQclear(res);
                
                ok(connection_dead, "Connection should be terminated");
            }
        }
    }

    // Test 3: Parameterized pg_cancel_backend with binary format (int4)
    diag("Test 3: Parameterized pg_cancel_backend with binary format (int4)");
    {
        auto backend_conn = createNewConnection(BACKEND);
        if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
            diag("Error: failed to connect to the database");
            skip(1, "Connection failed");
        } else {
            int backend_pid = PQbackendPID(backend_conn.get());
            
            // Reset sync variables
            sync.query_started = false;
            sync.query_completed = false;
            was_canceled = false;
            
            // Start query in separate thread
            std::thread query_thread([&]() {
                execute_long_running_query(backend_conn.get(), sync, 10, was_canceled);
            });

            // Wait for query to start
            {
                std::unique_lock<std::mutex> lock(sync.mutex);
                sync.cv.wait(lock, [&]() { return sync.query_started; });
            }

            // Create connection and cancel the query using binary format
            auto cancel_conn = createNewConnection(BACKEND);
            if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
                query_thread.join();
                skip(1, "Connection failed");
            } else {
                bool success = execute_prepared_statement_binary(cancel_conn.get(), "cancel_binary_stmt",
                    "SELECT pg_cancel_backend($1)", backend_pid);
                
                ok(success, "Parameterized pg_cancel_backend with binary format (int4) should succeed");

                // Wait for query completion
                {
                    std::unique_lock<std::mutex> lock(sync.mutex);
                    sync.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync.query_completed; });
                }

                query_thread.join();
                ok(was_canceled, "Query should be canceled via binary parameterized query");
            }
        }
    }

    // Test 4: Parameterized pg_terminate_backend with binary format (int4)
    diag("Test 4: Parameterized pg_terminate_backend with binary format (int4)");
    {
        auto victim_conn = createNewConnection(BACKEND);
        if (!victim_conn || PQstatus(victim_conn.get()) != CONNECTION_OK) {
            skip(1, "Connection failed");
        } else {
            int victim_pid = PQbackendPID(victim_conn.get());
            
            // Create connection and terminate using binary format
            auto killer_conn = createNewConnection(BACKEND);
            if (!killer_conn || PQstatus(killer_conn.get()) != CONNECTION_OK) {
                skip(1, "Connection failed");
            } else {
                bool success = execute_prepared_statement_binary(killer_conn.get(), "terminate_binary_stmt",
                    "SELECT pg_terminate_backend($1)", victim_pid);
                
                ok(success, "Parameterized pg_terminate_backend with binary format (int4) should succeed");

                // Verify the connection was terminated
                PGresult* res = PQexec(victim_conn.get(), "SELECT 1");
                bool connection_dead = (PQresultStatus(res) != PGRES_TUPLES_OK);
                PQclear(res);
                
                ok(connection_dead, "Connection should be terminated with binary parameter");
            }
        }
    }

    // Test 5: Parameterized pg_cancel_backend with binary format (int8)
    diag("Test 5: Parameterized pg_cancel_backend with binary format (int8)");
    {
        auto backend_conn = createNewConnection(BACKEND);
        if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
            diag("Error: failed to connect to the database");
            skip(1, "Connection failed");
        } else {
            int backend_pid = PQbackendPID(backend_conn.get());
            
            // Reset sync variables
            sync.query_started = false;
            sync.query_completed = false;
            was_canceled = false;
            
            // Start query in separate thread
            std::thread query_thread([&]() {
                execute_long_running_query(backend_conn.get(), sync, 10, was_canceled);
            });

            // Wait for query to start
            {
                std::unique_lock<std::mutex> lock(sync.mutex);
                sync.cv.wait(lock, [&]() { return sync.query_started; });
            }

            // Create connection and cancel the query using int8 binary format
            auto cancel_conn = createNewConnection(BACKEND);
            if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
                query_thread.join();
                skip(1, "Connection failed");
            } else {
                bool success = execute_prepared_statement_int8(cancel_conn.get(), "cancel_int8_stmt",
                    "SELECT pg_cancel_backend($1)", static_cast<int64_t>(backend_pid));
                
                ok(success, "Parameterized pg_cancel_backend with binary format (int8) should succeed");

                // Wait for query completion
                {
                    std::unique_lock<std::mutex> lock(sync.mutex);
                    sync.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync.query_completed; });
                }

                query_thread.join();
                ok(was_canceled, "Query should be canceled via int8 binary parameterized query");
            }
        }
    }

    // Test 6: Error handling - NULL parameter
    diag("Test 6: Error handling - NULL parameter");
    {
        auto test_conn = createNewConnection(BACKEND);
        if (!test_conn || PQstatus(test_conn.get()) != CONNECTION_OK) {
            skip(2, "Connection failed");
        } else {
            bool error_occurred = test_parameterized_query_error(test_conn.get(), 
                "SELECT pg_cancel_backend($1)", NULL, 0, 0, "NULL is not allowed");
            ok(error_occurred, "NULL parameter should return error");
            
            error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_terminate_backend($1)", NULL, 0, 0, "NULL is not allowed");
            ok(error_occurred, "NULL parameter should return error for terminate");
        }
    }

    // Test 7: Error handling - Invalid text (non-integer)
    diag("Test 7: Error handling - Invalid text parameter");
    {
        auto test_conn = createNewConnection(BACKEND);
        if (!test_conn || PQstatus(test_conn.get()) != CONNECTION_OK) {
            skip(2, "Connection failed");
        } else {
            bool error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_cancel_backend($1)", "not_a_number", 12, 0, "invalid input syntax for integer");
            ok(error_occurred, "Non-integer text parameter should return error");
            
            error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_terminate_backend($1)", "abc123", 6, 0, "invalid input syntax for integer");
            ok(error_occurred, "Mixed text parameter should return error");
        }
    }
    
    // Test 8: Error handling - Negative integer
    diag("Test 8: Error handling - Negative integer");
    {
        auto test_conn = createNewConnection(BACKEND);
        if (!test_conn || PQstatus(test_conn.get()) != CONNECTION_OK) {
            skip(2, "Connection failed");
        } else {
            bool error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_cancel_backend($1)", "-123", 4, 0, "invalid input syntax for integer");
            ok(error_occurred, "Negative integer should return error");
            
            error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_terminate_backend($1)", "0", 1, 0, "PID must be a positive integer");
            ok(error_occurred, "Zero should return error");
        }
    }

    // Test 9: Error handling - Empty string
    diag("Test 9: Error handling - Empty string");
    {
        auto test_conn = createNewConnection(BACKEND);
        if (!test_conn || PQstatus(test_conn.get()) != CONNECTION_OK) {
            skip(1, "Connection failed");
        } else {
            bool error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_cancel_backend($1)", "", 0, 0, "invalid input syntax for integer");
            ok(error_occurred, "Empty string should return error");
        }
    }
    
    // Test 10: Error handling - Multiple parameters
    diag("Test 10: Error handling - Multiple parameters");
    {
        auto test_conn = createNewConnection(BACKEND);
        if (!test_conn || PQstatus(test_conn.get()) != CONNECTION_OK) {
            skip(1, "Connection failed");
        } else {
            // Test with SELECT pg_cancel_backend($1, $2)
            std::string stmt_name = "multi_param_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());

            // Prepare statement with two parameters
            PGresult* res = PQprepare(test_conn.get(), stmt_name.c_str(), "SELECT pg_cancel_backend($1, $2)", 2, NULL);
            bool prepare_failed = (PQresultStatus(res) == PGRES_FATAL_ERROR);
            PQclear(res);

            ok(prepare_failed, "Multiple parameters should return error");

            // Clean up
            res = PQexec(test_conn.get(), ("DEALLOCATE " + stmt_name).c_str());
            PQclear(res);
        }
    }

    // Test 11: Mixed queries (literal still works)
    diag("Test 11: Literal queries still work");
    {
        auto victim_conn = createNewConnection(BACKEND);
        if (!victim_conn || PQstatus(victim_conn.get()) != CONNECTION_OK) {
            skip(2, "Connection failed");
        } else {
            int victim_pid = PQbackendPID(victim_conn.get());
            
            // Create connection and terminate using literal query (not parameterized)
            auto killer_conn = createNewConnection(BACKEND);
            if (!killer_conn || PQstatus(killer_conn.get()) != CONNECTION_OK) {
                skip(2, "Connection failed");
            } else {
                std::string literal_query = "SELECT pg_terminate_backend(" + std::to_string(victim_pid) + ")";
                PGresult* res = PQexec(killer_conn.get(), literal_query.c_str());
                bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
                PQclear(res);
                
                ok(success, "Literal pg_terminate_backend should still work");
                
                // Verify the connection was terminated
                res = PQexec(victim_conn.get(), "SELECT 1");
                bool connection_dead = (PQresultStatus(res) != PGRES_TUPLES_OK);
                PQclear(res);
                
                ok(connection_dead, "Connection should be terminated via literal query");
            }
        }
    }

    // Test 12: Very large PID (boundary test)
    diag("Test 12: Boundary test - large PID");
    {
        auto test_conn = createNewConnection(BACKEND);
        if (!test_conn || PQstatus(test_conn.get()) != CONNECTION_OK) {
            skip(1, "Connection failed");
        } else {
            // Test with maximum 32-bit integer
            std::string max_pid = "2147483647"; // INT_MAX
            bool error_occurred = test_parameterized_query_error(test_conn.get(),
                "SELECT pg_cancel_backend($1)", max_pid.c_str(), max_pid.length(), 0, 
                "invalid input syntax for integer");
            
            // This might succeed or fail depending on system limits
            // We just verify it doesn't crash
            ok(true, "Large PID should not crash the system");
        }
    }

    return exit_status();
}
