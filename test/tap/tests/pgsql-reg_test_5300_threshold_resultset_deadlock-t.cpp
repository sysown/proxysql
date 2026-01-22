/**
 * @file pgsql-reg_test_5300_threshold_resultset_deadlock-t.cpp
 * @brief Regression test for Close Statement + threshold_resultset_size deadlock bug
 *
 * BUG DESCRIPTION:
 * ProxySQL can enter an infinite loop/deadlock when the following conditions occur:
 *
 * 1. A prepared statement operation is sent that requires backend routing
 *    (Prepare, Describe, Execute - operations that need backend connection)
 * 2. Followed by many Close Statement messages (1000s) that DON'T require backend routing
 *    (Close operations are handled locally by ProxySQL)
 * 3. These Close responses accumulate in PSarrayOUT and exceed pgsql-threshold_resultset_size
 * 4. Then another backend operation (Describe/Execute) is sent in the same extended query frame
 *
 * ROOT CAUSE:
 * ProxySQL has logic to stop reading from backend when client PSarrayOUT exceeds threshold_resultset_size
 * (this prevents memory bloat when client is slow at receiving data). However, Close Statement
 * responses are handled by ProxySQL itself and don't require backend interaction. When threshold
 * is exceeded by Close responses, ProxySQL stops reading from backend, but the backend operation
 * (Describe/Execute) is waiting on the backend. This creates a deadlock:
 * - ProxySQL won't read from backend (threshold exceeded)
 * - Backend operation can't complete (ProxySQL not reading)
 * - Extended query frame never completes
 * - Query times out
 *
 * THE FIX:
 * When PSarrayOUT exceeds threshold_resultset_size and a backend operation is pending,
 * ProxySQL flushes all accumulated data in PSarrayOUT to the client first, then continues
 * processing backend operations. This breaks the deadlock by clearing the buffer before
 * attempting to read more data from the backend.
 *
 *
 * TEST STRATEGY:
 * - Use pg_lite_client.h to send raw protocol messages
 * - Send all operations in ONE extended query frame (no Sync until the end)
 * - Verify ProxySQL doesn't hang and completes all operations
 */

#include <string>
#include <vector>
#include <memory>
#include <sstream>
#include <cstring>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "pg_lite_client.h"
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

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
    auto fnResultType = [](const char* query) -> int {
        const char* fs = strchr(query, ' ');
        // NOSONAR: strlen is safe here as we control the input
        size_t qtlen = strlen(query); // NOSONAR
        if (fs != NULL) {
            qtlen = (fs - query) + 1;
        }
        char buf[qtlen];
        memcpy(buf, query, qtlen - 1);
        buf[qtlen - 1] = 0;

        if (strncasecmp(buf, "SELECT", sizeof("SELECT") - 1) == 0) {
            return PGRES_TUPLES_OK;
        }
        else if (strncasecmp(buf, "COPY", sizeof("COPY") - 1) == 0) {
            return PGRES_COPY_OUT;
        }

        return PGRES_COMMAND_OK;
        };


    for (const auto& query : queries) {
        diag("Running: %s", query.c_str());
        PGresult* res = PQexec(conn, query.c_str());
        bool success = PQresultStatus(res) == fnResultType(query.c_str());
        if (!success) {
            fprintf(stderr, "Failed to execute query '%s': %s\n",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

std::shared_ptr<PgConnection> create_pglite_connection() {
    auto conn = std::make_shared<PgConnection>(5000);
    try {
        conn->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
    }
    catch (const PgException& e) {
        diag("Connection failed: %s", e.what());
        return nullptr;
    }
    return conn;
}

/**
 * Test 1: Deadlock scenario with Close Statement flood + Describe (backend operation)
 *
 * BUG REPRODUCTION:
 * 1. Prepare statement (backend operation - requires backend connection, but connection
 *    is not sticky for the entire frame, can be released back to pool)
 * 2. Send 5000 Close Statement messages (NO backend routing - handled by ProxySQL)
 *    - These accumulate CloseComplete responses in PSarrayOUT
 *    - Total size exceeds pgsql-threshold_resultset_size (set to 1024 bytes)
 * 3. Send Describe (backend operation - requires backend connection)
 * 4. Send Sync to complete extended query frame
 *
 * EXPECTED BUG BEHAVIOR (before fix):
 * - PSarrayOUT exceeds threshold after Close operations
 * - ProxySQL stops reading from backend (to prevent memory bloat)
 * - Describe needs backend response, but ProxySQL won't read it
 * - Deadlock: extended query frame never completes
 * - Query times out
 *
 * EXPECTED BEHAVIOR (after fix):
 * - ProxySQL recognizes that Close responses don't require backend throttling, OR
 * - ProxySQL completes the extended query frame despite threshold being exceeded
 * - All operations complete successfully without timeout
 */
void test_close_flood_then_describe_deadlock() {
    diag("\n=== Test 1: Close Statement Flood -> Describe (Deadlock Regression) ===\n");

    auto conn = create_pglite_connection();
    if (!conn) {
        skip(1, "Failed to create connection");
        return;
    }

    try {
        const std::string stmt_name = "deadlock_test_describe";
        const std::string query = "SELECT $1::text";

        // CRITICAL: All operations below are in ONE extended query frame (no Sync until end)

        diag("\n--- Starting Deadlock Scenario ---");

        // Step 1: Prepare statement (backend operation)
        // This establishes the prepared statement but connection is NOT sticky
        diag("Step 1: Prepare statement (backend operation, connection not sticky)");
        conn->prepareStatement(stmt_name, query, false);

        // Step 2: Initial Describe to verify statement exists (backend operation)
        diag("Step 2: Initial Describe to establish statement");
        conn->describeStatement(stmt_name, false);

        // Step 3: Send flood of Close Statement messages (NO backend routing)
        // These are handled by ProxySQL itself, don't need backend
        const int close_count = 5000;
        diag("Step 3: Flooding with %d Close Statement messages (no backend routing)", close_count);
        diag("        These will accumulate CloseComplete responses in PSarrayOUT");
        diag("        Total size will exceed threshold_resultset_size (1024 bytes)");

        for (int i = 0; i < close_count; i++) {
            // Close non-existent statements - ProxySQL handles these locally
            conn->closeStatement("dummy_stmt_" + std::to_string(i), false);
        }

        // Step 4: Send Describe (backend operation - REQUIRES backend connection)
        // This is where the deadlock occurs!
        // PSarrayOUT is over threshold, ProxySQL won't read from backend
        // But Describe needs backend response to complete
        diag("Step 4: Sending Describe (backend operation - DEADLOCK TRIGGER)");
        diag("        Bug: ProxySQL won't read from backend (threshold exceeded)");
        diag("        Bug: But this Describe needs backend response to complete");
        conn->describeStatement(stmt_name, false);

        // Step 5: Send Sync to complete extended query frame
        diag("Step 5: Sending Sync to complete extended query frame");
        conn->sendSync();

        // Step 6: Wait for completion
        // Before fix: This would timeout (deadlock)
        // After fix: This completes successfully
        diag("Step 6: Waiting for frame completion (this would timeout before fix)...");
        conn->waitForReady();

        ok(true, "REGRESSION TEST PASSED: Close flood + Describe completed without deadlock");

    }
    catch (const PgException& e) {
        ok(false, "REGRESSION TEST FAILED: Deadlock occurred - %s", e.what());
        return;
    }
}

/**
 * Test 2: Deadlock scenario with Close Statement flood + Execute (backend operation)
 *
 * Same bug, different backend operation (Execute instead of Describe).
 *
 * BUG REPRODUCTION:
 * 1. Prepare statement (backend operation)
 * 2. Send 5000 Close Statement messages (NO backend routing)
 *    - Accumulate CloseComplete responses exceeding threshold_resultset_size
 * 3. Send Bind + Execute (backend operations)
 * 4. Send Sync to complete extended query frame
 *
 * Same deadlock mechanism as Test 1, but with Execute instead of Describe.
 */
void test_close_flood_then_execute_deadlock() {
    diag("\n=== Test 2: Close Statement Flood -> Execute (Deadlock Regression) ===\n");

    auto conn = create_pglite_connection();
    if (!conn) {
        skip(1, "Failed to create connection");
        return;
    }

    try {
        const std::string stmt_name = "deadlock_test_execute";
        const std::string query = "SELECT $1::text";

        diag("\n--- Starting Deadlock Scenario ---");

        // Step 1 & 2: Prepare and describe statement (backend operations)
        diag("Step 1-2: Prepare and Describe statement (setup)");
        conn->prepareStatement(stmt_name, query, false);
        conn->describeStatement(stmt_name, false);

        // Step 3: Send flood of Close Statement messages (NO backend routing)
        const int close_count = 5000;
        diag("Step 3: Flooding with %d Close Statement messages (no backend routing)", close_count);
        diag("        CloseComplete responses will exceed threshold_resultset_size");

        for (int i = 0; i < close_count; i++) {
            conn->closeStatement("dummy_stmt_" + std::to_string(i), false);
        }

        // Step 4: Send Bind (backend operation)
        diag("Step 4: Sending Bind (backend operation)");
        std::vector<PgConnection::Param> params;
        params.push_back({ "test_value", 0 }); // text format
        conn->bindStatement(stmt_name, "", params, {}, false);

        // Step 5: Send Execute (backend operation - DEADLOCK TRIGGER)
        diag("Step 5: Sending Execute (backend operation - DEADLOCK TRIGGER)");
        diag("        Bug: PSarrayOUT over threshold, ProxySQL won't read from backend");
        diag("        Bug: But Execute needs backend response (DataRow, CommandComplete)");
        conn->executePortal("", 0, false);

        // Step 6: Send Sync to complete extended query frame
        diag("Step 6: Sending Sync to complete extended query frame");
        conn->sendSync();

        // Step 7: Wait for completion
        diag("Step 7: Waiting for frame completion (this would timeout before fix)...");
        conn->waitForReady();

        ok(true, "REGRESSION TEST PASSED: Close flood + Execute completed without deadlock");

    }
    catch (const PgException& e) {
        ok(false, "REGRESSION TEST FAILED: Deadlock occurred - %s", e.what());
        return;
    }
}

int main(int argc, char** argv) {
    plan(2);

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    auto admin_conn = createNewConnection(ConnType::ADMIN, "", false);

    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

    // CRITICAL: Set threshold_resultset_size to LOW value (1024 bytes)
    // This ensures Close Statement responses will exceed the threshold
    // and trigger the deadlock condition
    diag("\n=== Configuring ProxySQL for Deadlock Test ===");
    diag("Setting pgsql-threshold_resultset_size=1024 (LOW threshold to trigger bug)");
    diag("With 5000 Close responses, PSarrayOUT will exceed this threshold");

    if (executeQueries(admin_conn.get(), {
        "SET pgsql-authentication_method=1",
        "SET pgsql-threshold_resultset_size=1024",  // LOW threshold to trigger deadlock
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }) == false) {
        BAIL_OUT("Error: failed to configure ProxySQL settings in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

    // Run regression tests
    test_close_flood_then_describe_deadlock();
    test_close_flood_then_execute_deadlock();

    return exit_status();
}
