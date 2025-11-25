/**
 * @file pgsql-query_cancel_session_termination_test-t.cpp
 * @brief TAP test verifying ProxySQL query cancellation and session termination.
 * 
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
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

// Test synchronization utilities
struct TestSync {
    std::mutex mutex;
    std::condition_variable cv;
    bool query_started = false;
    bool cancel_requested = false;
    bool query_completed = false;
};

// Test query that runs for a long time
const char* LONG_RUNNING_QUERY = "SELECT pg_sleep(10), generate_series(1, 1000000)";

// Function to execute query and handle results
void execute_long_running_query(PGconn* conn, TestSync& sync, int thread_id, bool& was_canceled) {
    was_canceled = false;

    // Notify that query is starting
    {
        std::lock_guard<std::mutex> lock(sync.mutex);
        sync.query_started = true;
    }
    sync.cv.notify_one();

    // Execute query
    PGresult* res = PQexec(conn, LONG_RUNNING_QUERY);

    // Check result
    if (res == nullptr) {
        std::lock_guard<std::mutex> lock(sync.mutex);
        sync.query_completed = true;
        return;
    }

    ExecStatusType status = PQresultStatus(res);
    PQclear(res);

    {
        std::lock_guard<std::mutex> lock(sync.mutex);
        sync.query_completed = true;
        was_canceled = (status == PGRES_FATAL_ERROR &&
            std::string(PQerrorMessage(conn)).find("canceling statement due to user request") != std::string::npos);
    }
    sync.cv.notify_one();
}

// Test 1: Cancel query using new connection method
void test_cancel_via_new_connection() {
    diag("Test 1: Cancel query using new connection method");

    // Create main connection for long-running query
    auto backend_conn = createNewConnection(BACKEND);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    int backend_pid = PQbackendPID(backend_conn.get());

    // Get backend PID for cancellation
    PGresult* res = PQexec(backend_conn.get(), "SELECT pg_backend_pid()");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Should get backend PID");

    int query_backend_pid = std::stoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    ok(backend_pid == query_backend_pid, "Connection and query report the same backend PID");
    
    TestSync sync;
    bool was_canceled = false;

    // Start query in separate thread
    std::thread query_thread([&]() {
        execute_long_running_query(backend_conn.get(), sync, 1, was_canceled);
        });

    // Wait for query to start
    {
        std::unique_lock<std::mutex> lock(sync.mutex);
        sync.cv.wait(lock, [&]() { return sync.query_started; });
    }

    // Create connection and cancel the query
    auto cancel_conn = createNewConnection(BACKEND);
    if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
        query_thread.join();
        diag("Error: Failed to create connection for cancellation in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    std::string cancel_query = "SELECT pg_cancel_backend(" + std::to_string(backend_pid) + ")";
    res = PQexec(cancel_conn.get(), cancel_query.c_str());
    bool cancel_success = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    ok(cancel_success, "Cancel query should execute successfully");

    // Wait for query completion
    {
        std::unique_lock<std::mutex> lock(sync.mutex);
        sync.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync.query_completed; });
    }

    query_thread.join();

    ok(was_canceled, "Query should be canceled via new connection method");
}

// Test 2: Cancel query using PQcancel method
void test_cancel_via_pqcancel() {
    diag("Test 2: Cancel query using PQcancel method");

    // Create connection for long-running query
    auto backend_conn = createNewConnection(BACKEND);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    TestSync sync;
    bool was_canceled = false;

    // Start query in separate thread
    std::thread query_thread([&]() {
        execute_long_running_query(backend_conn.get(), sync, 2, was_canceled);
        });

    // Wait for query to start
    {
        std::unique_lock<std::mutex> lock(sync.mutex);
        sync.cv.wait(lock, [&]() { return sync.query_started; });
    }

    // Use PQcancel to cancel the query
    PGcancel* cancel = PQgetCancel(backend_conn.get());
    if (!cancel) {
        query_thread.join();
        diag("Error: Failed to get cancel object in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    char errbuf[256];
    int cancel_result = PQcancel(cancel, errbuf, sizeof(errbuf));
    PQfreeCancel(cancel);


    ok(cancel_result == 1, "PQcancel should return success");

    // Wait for query completion
    {
        std::unique_lock<std::mutex> lock(sync.mutex);
        sync.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync.query_completed; });
    }

    query_thread.join();

   ok(was_canceled, "Query should be canceled via PQcancel method");
}

// Test 3: Terminate backend connection
void test_terminate_backend() {
    diag("Test 3: Terminate backend connection");

    // Create connection that will be terminated
    auto victim_conn = createNewConnection(BACKEND);
    if (!victim_conn || PQstatus(victim_conn.get()) != CONNECTION_OK) {
        diag("Error: Failed to create victim backend connection in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    int victim_backend_pid = PQbackendPID(victim_conn.get());

    // Get victim backend PID
    PGresult* res = PQexec(victim_conn.get(), "SELECT pg_backend_pid()");

    ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Should get backend PID (victim)");

    int query_backend_pid = std::stoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    ok(victim_backend_pid == query_backend_pid, "Connection and query report the same victim backend PID");

    // Create connection and cancel the query
    auto cancel_conn = createNewConnection(BACKEND);
    if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
        diag("Error: Failed to create connection for cancellation in file %s, line %d", __FILE__, __LINE__);
        return;
    }
    // Terminate the backend
    std::string terminate_query = "SELECT pg_terminate_backend(" + std::to_string(victim_backend_pid) + ")";
    res = PQexec(cancel_conn.get(), terminate_query.c_str());
    bool terminate_success = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    ok(terminate_success, "Terminate query should execute successfully");

    // Verify victim connection is terminated by trying to execute a simple query
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Small delay for termination to take effect

    res = PQexec(victim_conn.get(), "SELECT 1");
    bool connection_dead = (PQstatus(victim_conn.get()) == CONNECTION_BAD ||
        PQresultStatus(res) != PGRES_TUPLES_OK);
    if (res) PQclear(res);

    ok(connection_dead, "Victim connection should be terminated");
}

// Test 4: Multiple concurrent cancellations
void test_multiple_concurrent_cancellations() {
    diag("Test 4: Multiple concurrent cancellations");

    const int NUM_CONNECTIONS = 3;
    std::vector<PGConnPtr> connections;
    std::vector<int> backend_pids;
    std::vector<std::thread> query_threads;
    std::vector<TestSync> syncs(NUM_CONNECTIONS);
    std::vector<uint8_t> was_canceled(NUM_CONNECTIONS, false);
    std::vector<bool> tests_passed(NUM_CONNECTIONS, false);

    // Create multiple backend connections
    for (int i = 0; i < NUM_CONNECTIONS; i++) {
        auto backend_conn = createNewConnection(BACKEND);
        if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
            diag("Error: failed to backend connection in file %s, line %d", __FILE__, __LINE__);
            return;
        }

        int backend_pid = PQbackendPID(backend_conn.get());

        // Get backend PID
        PGresult* res = PQexec(backend_conn.get(), "SELECT pg_backend_pid()");
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            diag("Failed to get backend PID %d", i);
            PQclear(res);
            continue;
        }
        int query_backend_pid = std::stoi(PQgetvalue(res, 0, 0));
        PQclear(res);

        ok(backend_pid == query_backend_pid, "Connection and query report the same backend PID");

        connections.push_back(std::move(backend_conn));
        backend_pids.push_back(backend_pid);
    }

    ok(connections.size() == NUM_CONNECTIONS, "Successfully created all backend connections");
    
    // Start long-running queries on all connections
    for (int i = 0; i < NUM_CONNECTIONS; i++) {
        query_threads.emplace_back([&, i]() {
            execute_long_running_query(connections[i].get(), syncs[i], i, (bool&)was_canceled[i]);
            });
    }

    // Wait for all queries to start
    for (int i = 0; i < NUM_CONNECTIONS; i++) {
        std::unique_lock<std::mutex> lock(syncs[i].mutex);
        syncs[i].cv.wait(lock, [&, i]() { return syncs[i].query_started; });
    }

    // Create connection and cancel the query
    auto cancel_conn = createNewConnection(BACKEND);
    if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
        for (auto& thread : query_threads) thread.join();
        diag("Error: Failed to create connection for cancellation in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    bool all_cancels_successful = true;
    for (int i = 0; i < NUM_CONNECTIONS; i++) {
        std::string cancel_query = "SELECT pg_cancel_backend(" + std::to_string(backend_pids[i]) + ")";
        PGresult* res = PQexec(cancel_conn.get(), cancel_query.c_str());
        bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
        PQclear(res);

        if (!success) {
            all_cancels_successful = false;
            diag("Cancel failed for connection %d", i);
        }
    }

    ok(all_cancels_successful, "All cancel queries should execute successfully");

    // Wait for all queries to complete
    for (int i = 0; i < NUM_CONNECTIONS; i++) {
        std::unique_lock<std::mutex> lock(syncs[i].mutex);
        syncs[i].cv.wait_for(lock, std::chrono::seconds(3), [&, i]() { return syncs[i].query_completed; });
    }

    // Join all threads
    for (auto& thread : query_threads) {
        thread.join();
    }

    // Verify all queries were canceled
    bool all_canceled = true;
    for (int i = 0; i < NUM_CONNECTIONS; i++) {
        if (!was_canceled[i]) {
            all_canceled = false;
            diag("Query '%d' was not canceled", i);
        }
    }

    ok(all_canceled, "All queries should be canceled");
}

// Test 5: Verify correct query/connection is affected
void test_target_specificity() {
    diag("Test 5: Verify cancellation affects only target query/connection");

    // Create two backend connections
    auto backend_conn1 = createNewConnection(BACKEND);
    if (!backend_conn1 || PQstatus(backend_conn1.get()) != CONNECTION_OK) {
        diag("Error: failed to backend connection in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    auto backend_conn2 = createNewConnection(BACKEND);
    if (!backend_conn2 || PQstatus(backend_conn2.get()) != CONNECTION_OK) {
        diag("Error: failed to backend connection in file %s, line %d", __FILE__, __LINE__);
        return;
    }

	int backend_pid1 = PQbackendPID(backend_conn1.get());
	int backend_pid2 = PQbackendPID(backend_conn2.get());

    // Get backend PIDs
    PGresult* res1 = PQexec(backend_conn1.get(), "SELECT pg_backend_pid()");
    PGresult* res2 = PQexec(backend_conn2.get(), "SELECT pg_backend_pid()");

    ok(PQresultStatus(res1) == PGRES_TUPLES_OK && PQresultStatus(res2) == PGRES_TUPLES_OK, "Should get backend PIDs");

    int pid1 = std::stoi(PQgetvalue(res1, 0, 0));
    int pid2 = std::stoi(PQgetvalue(res2, 0, 0));
    PQclear(res1);
    PQclear(res2);

	ok(backend_pid1 == pid1, "Connection 1 and query report the same backend PID");
	ok(backend_pid2 == pid2, "Connection 2 and query report the same backend PID");

    TestSync sync1, sync2;
    bool was_canceled1 = false, was_canceled2 = false;

    // Start long-running query on connection 1
    std::thread thread1([&]() {
        execute_long_running_query(backend_conn1.get(), sync1, 1, was_canceled1);
        });

    // Wait for query to start on connection 1
    {
        std::unique_lock<std::mutex> lock(sync1.mutex);
        sync1.cv.wait(lock, [&]() { return sync1.query_started; });
    }

    // Execute simple query on connection 2 (should not be affected)
    PGresult* simple_res = PQexec(backend_conn2.get(), "SELECT 1");
    bool conn2_healthy = (PQresultStatus(simple_res) == PGRES_TUPLES_OK);
    PQclear(simple_res);

    ok(conn2_healthy, "Connection 2 should remain healthy during connection 1's long query");

    // Create connection and cancel the query
    auto cancel_conn = createNewConnection(BACKEND);
    if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
        thread1.join();
        diag("Error: Failed to create connection for cancellation in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    std::string cancel_query = "SELECT pg_cancel_backend(" + std::to_string(backend_pid1) + ")";
    PGresult* cancel_res = PQexec(cancel_conn.get(), cancel_query.c_str());
    bool cancel_success = (PQresultStatus(cancel_res) == PGRES_TUPLES_OK);
    PQclear(cancel_res);

    ok(cancel_success, "Cancel should succeed for connection 1");

    // Wait for connection 1's query to complete
    {
        std::unique_lock<std::mutex> lock(sync1.mutex);
        sync1.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync1.query_completed; });
    }

    thread1.join();

    // Verify connection 2 is still healthy
    simple_res = PQexec(backend_conn2.get(), "SELECT 1");
    conn2_healthy = (PQresultStatus(simple_res) == PGRES_TUPLES_OK);
    PQclear(simple_res);

    bool test_result = was_canceled1 && conn2_healthy;

    ok(test_result, "Only target query should be canceled, other connection should remain healthy");
}

// Test 6: Cancel extended query protocol operations
void test_cancel_extended_query() {
    diag("Test 6: Cancel extended query protocol operations");

    // Create connection for extended query
    auto backend_conn = createNewConnection(BACKEND);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: Failed to create backend connection for extended query in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    TestSync sync;
    bool was_canceled = false;

    int backend_pid = PQbackendPID(backend_conn.get());

    // Get backend PID for cancellation
    PGresult* res = PQexec(backend_conn.get(), "SELECT pg_backend_pid()");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Should get backend PID");

    int query_backend_pid = std::stoi(PQgetvalue(res, 0, 0));
    PQclear(res);

    ok(backend_pid == query_backend_pid, "Connection and query report the same backend PID");

    // Start extended query in separate thread
    std::thread query_thread([&]() {
        // Use extended query protocol: Parse, Bind, Execute
        const char* query_name = "long_running_query";
        const char* query_text = "SELECT pg_sleep(5), $1::text";

        // Parse
        PGresult* parse_res = PQprepare(backend_conn.get(), query_name, query_text, 1, NULL);
        if (PQresultStatus(parse_res) != PGRES_COMMAND_OK) {
            PQclear(parse_res);
            std::lock_guard<std::mutex> lock(sync.mutex);
            sync.query_completed = true;
            return;
        }
        PQclear(parse_res);

        // Notify that query is starting
        {
            std::lock_guard<std::mutex> lock(sync.mutex);
            sync.query_started = true;
        }
        sync.cv.notify_one();

        // Bind parameters
        const char* param_values[1] = { "test_parameter" };
        const int param_lengths[1] = { static_cast<int>(strlen(param_values[0])) };
        const int param_formats[1] = { 0 }; // text format

        // Execute - this should be cancellable
        PGresult* exec_res = PQexecPrepared(backend_conn.get(), query_name, 1, param_values,
            param_lengths, param_formats, 0);

        if (exec_res == nullptr) {
            std::lock_guard<std::mutex> lock(sync.mutex);
            sync.query_completed = true;
            return;
        }

        ExecStatusType status = PQresultStatus(exec_res);
        PQclear(exec_res);

        {
            std::lock_guard<std::mutex> lock(sync.mutex);
            sync.query_completed = true;
            was_canceled = (status == PGRES_FATAL_ERROR &&
                std::string(PQerrorMessage(backend_conn.get())).find("canceling statement due to user request") != std::string::npos);
        }
        sync.cv.notify_one();
        });

    // Wait for query to start
    {
        std::unique_lock<std::mutex> lock(sync.mutex);
        sync.cv.wait(lock, [&]() { return sync.query_started; });
    }

    // Cancel using admin connection
    auto cancel_conn = createNewConnection(BACKEND);
    if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
        query_thread.join();
        diag("Error: Failed to create cancel connection for extended query cancellation in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    std::string cancel_query = "SELECT pg_cancel_backend(" + std::to_string(backend_pid) + ")";
    PGresult* cancel_res = PQexec(cancel_conn.get(), cancel_query.c_str());
    bool cancel_success = (PQresultStatus(cancel_res) == PGRES_TUPLES_OK);
    PQclear(cancel_res);

    ok(cancel_success, "Cancel should succeed for extended query");

    // Wait for query completion
    {
        std::unique_lock<std::mutex> lock(sync.mutex);
        sync.cv.wait_for(lock, std::chrono::seconds(3), [&]() { return sync.query_completed; });
    }

    query_thread.join();

    ok(was_canceled, "Extended query should be canceled successfully");
}

// Test 7: Multiple session termination with specificity check
void test_multiple_session_termination() {
    diag("Test 7: Multiple session termination with specificity check");

    const int TOTAL_CONNECTIONS = 5;
    const int TERMINATE_COUNT = 2;

    std::vector<PGConnPtr> connections;
    std::vector<int> backend_pids;
    std::vector<bool> connection_alive(TOTAL_CONNECTIONS, true);

    // Create multiple backend connections
    for (int i = 0; i < TOTAL_CONNECTIONS; i++) {
        auto backend_conn = createNewConnection(BACKEND);
        if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
            diag("Error: Failed to backend connection '%d' in file %s, line %d", i, __FILE__, __LINE__);
            return;
        }

        int backend_pid = PQbackendPID(backend_conn.get());

        // Get backend PID
        PGresult* res = PQexec(backend_conn.get(), "SELECT pg_backend_pid()");
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            diag("Failed to get backend PID %d", i);
            PQclear(res);
            continue;
        }
        int query_backend_pid = std::stoi(PQgetvalue(res, 0, 0));
        PQclear(res);

        ok(backend_pid == query_backend_pid, "Connection and query report the same backend PID");

        connections.push_back(std::move(backend_conn));
        backend_pids.push_back(backend_pid);
    }

    auto cancel_conn = createNewConnection(BACKEND);
    if (!cancel_conn || PQstatus(cancel_conn.get()) != CONNECTION_OK) {
        diag("Error: Failed to create connection for cancellation in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    // Terminate only specific connections (first TERMINATE_COUNT)
    bool all_terminations_successful = true;
    for (int i = 0; i < TERMINATE_COUNT; i++) {
        std::string terminate_query = "SELECT pg_terminate_backend(" + std::to_string(backend_pids[i]) + ")";
        PGresult* res = PQexec(cancel_conn.get(), terminate_query.c_str());
        bool success = (PQresultStatus(res) == PGRES_TUPLES_OK);
        PQclear(res);

        if (!success) {
            all_terminations_successful = false;
            diag("Termination failed for connection %d", i);
        }
    }

    ok(all_terminations_successful, "All termination queries should execute successfully");

    // Small delay for terminations to take effect
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Check which connections are alive
    for (int i = 0; i < TOTAL_CONNECTIONS; i++) {
        PGresult* res = PQexec(connections[i].get(), "SELECT 1");
        connection_alive[i] = (PQresultStatus(res) == PGRES_TUPLES_OK);
        if (res) PQclear(res);
    }

    // Verify terminated connections are dead
    bool terminated_connections_dead = true;
    for (int i = 0; i < TERMINATE_COUNT; i++) {
        if (connection_alive[i]) {
            terminated_connections_dead = false;
            diag("Connection '%d' should be terminated but is still alive", i);
        }
    }

    ok(terminated_connections_dead, "Terminated connections should be dead");

    // Verify non-terminated connections are still alive
    bool alive_connections_healthy = true;
    for (int i = TERMINATE_COUNT; i < TOTAL_CONNECTIONS; i++) {
        if (!connection_alive[i]) {
            alive_connections_healthy = false;
            diag("Connection '%d' should be alive but is dead", i);
        }
    }

    ok(alive_connections_healthy, "Non-targeted connections should remain healthy");
}

int main(int argc, char** argv) {

    if (cl.getEnv())
        return exit_status();

    plan(34);
    
    test_cancel_via_new_connection();
    test_cancel_via_pqcancel();
    test_terminate_backend();
    test_multiple_concurrent_cancellations();
    test_target_specificity();
    test_cancel_extended_query();
    test_multiple_session_termination();

    return exit_status();
}
