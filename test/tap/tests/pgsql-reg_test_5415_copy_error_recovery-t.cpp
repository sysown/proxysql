/**
 * @file pgsql-reg_test_5415_copy_error_recovery-t.cpp
 * @brief Tests COPY FROM ... STDIN error recovery in ProxySQL
 *
 * When a COPY FROM STDIN operation encounters an error, the session switches back to normal mode. 
 * However, the client may have already pipelined CopyData('d'), CopyDone('c'), or CopyFail('f') messages 
 * that are still in the input queue. These messages fell through to the default case of message handler, 
 * generating a spurious "Feature not supported" error.
 *
 * This is a regression test for proper session state recovery after a failed COPY
 * command that entered fast_forward mode.
 */

#include <string>
#include <sstream>
#include <memory>
#include <vector>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

/**
 * @brief Creates a new PostgreSQL connection
 * @param with_ssl Whether to use SSL for the connection
 * @return A unique pointer to the PGconn structure
 */
PGConnPtr createNewConnection(bool with_ssl) {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
    ss << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;
    ss << " dbname=postgres";
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

/**
 * @brief Executes a single query and checks the result status
 * @param conn The PostgreSQL connection
 * @param query The query to execute
 * @param expected_status The expected result status
 * @return true if the query succeeded with expected status, false otherwise
 */
bool executeQuery(PGconn* conn, const char* query, ExecStatusType expected_status = PGRES_COMMAND_OK) {
    PGresult* res = PQexec(conn, query);
    bool success = PQresultStatus(res) == expected_status;
    if (!success) {
        diag("Query '%s' failed: %s", query, PQerrorMessage(conn));
    }
    PQclear(res);
    return success;
}

/**
 * @brief Setup test table
 * @param conn The PostgreSQL connection
 * @return true if setup succeeded, false otherwise
 */
bool setupTestTable(PGconn* conn) {
    PGresult* res = PQexec(conn, "DROP TABLE IF EXISTS copy_freeze_test");
    PQclear(res);

    res = PQexec(conn, "CREATE TABLE copy_freeze_test (id int, name text)");
    bool success = PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!success) {
        diag("Failed to create table: %s", PQerrorMessage(conn));
    }
    PQclear(res);
    return success;
}

/**
 * @brief Cleanup test table
 * @param conn The PostgreSQL connection
 */
void cleanupTestTable(PGconn* conn) {
    PGresult* res = PQexec(conn, "DROP TABLE IF EXISTS copy_freeze_test");
    PQclear(res);
}

/**
 * @brief Test 1: COPY FREEZE fails immediately and session recovers
 *
 * This test verifies that when a COPY ... FREEZE command fails because the table
 * was not created or truncated in the current subtransaction, the session properly
 * returns to normal mode and subsequent queries work correctly.
 *
 * @param conn The PostgreSQL connection
 */
void testCopyFreezeFailsImmediately(PGconn* conn) {
    diag("Test: COPY FREEZE fails immediately (table not truncated in current transaction)");

    // Execute COPY FREEZE - this should fail because table was not truncated
    // in the current subtransaction
    PGresult* res = PQexec(conn, "COPY copy_freeze_test FROM stdin CSV FREEZE");

    // The COPY may return PGRES_COPY_IN (if server sends CopyIn before error)
    // or PGRES_FATAL_ERROR (if server sends error immediately)
    ExecStatusType status = PQresultStatus(res);

    if (status == PGRES_COPY_IN) {
        diag("COPY entered COPY_IN mode, sending data...");

        // Send data - but backend will reject it
        if (PQputCopyData(conn, "1,test1\n", 8) != 1) {
            diag("PQputCopyData failed: %s", PQerrorMessage(conn));
        }
        if (PQputCopyEnd(conn, NULL) != 1) {
            diag("PQputCopyEnd failed: %s", PQerrorMessage(conn));
        }

        // Get the final result
        PQclear(res);
        res = PQgetResult(conn);
        status = PQresultStatus(res);
    }

    // The COPY should fail
    ok(status == PGRES_FATAL_ERROR,
       "COPY FREEZE should fail when table not truncated in current transaction: %s",
       PQresultErrorMessage(res));
    PQclear(res);

    // Consume any remaining results
    while ((res = PQgetResult(conn)) != NULL) {
        PQclear(res);
    }

    diag("Testing subsequent queries after COPY error...");

    // Test: BEGIN should work
    res = PQexec(conn, "BEGIN");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "BEGIN should work after COPY error: %s", PQerrorMessage(conn));
    PQclear(res);

    // Test: TRUNCATE should work
    res = PQexec(conn, "TRUNCATE copy_freeze_test");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "TRUNCATE should work: %s", PQerrorMessage(conn));
    PQclear(res);

    // Test: SAVEPOINT should work
    res = PQexec(conn, "SAVEPOINT s1");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "SAVEPOINT should work: %s", PQerrorMessage(conn));
    PQclear(res);

    // Test: COMMIT should work
    res = PQexec(conn, "COMMIT");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "COMMIT should work: %s", PQerrorMessage(conn));
    PQclear(res);
}

/**
 * @brief Test 2: COPY FREEZE succeeds when properly set up
 *
 * This test verifies that COPY ... FREEZE works correctly when the table
 * is properly truncated within the same transaction before the COPY command.
 *
 * IMPORTANT: COPY FREEZE requires that the table was created or truncated
 * in the CURRENT subtransaction. Using SAVEPOINT between TRUNCATE and COPY
 * FREEZE will cause failure because TRUNCATE is then in the parent subtransaction.
 *
 * @param conn The PostgreSQL connection
 */
void testCopyFreezeSucceedsWithProperSetup(PGconn* conn) {
    diag("Test: COPY FREEZE succeeds with proper transaction setup (no savepoint between TRUNCATE and COPY)");

    // Begin transaction
    PGresult* res = PQexec(conn, "BEGIN");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "BEGIN should succeed: %s", PQerrorMessage(conn));
    PQclear(res);

    // Truncate table in same transaction
    // NOTE: No SAVEPOINT here - COPY FREEZE requires TRUNCATE in current subtransaction
    res = PQexec(conn, "TRUNCATE copy_freeze_test");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "TRUNCATE should succeed: %s", PQerrorMessage(conn));
    PQclear(res);

    // Now COPY FREEZE should work (TRUNCATE is in same subtransaction)
    res = PQexec(conn, "COPY copy_freeze_test FROM stdin CSV FREEZE");
    ok(PQresultStatus(res) == PGRES_COPY_IN,
       "COPY FREEZE should enter COPY_IN mode: %s", PQerrorMessage(conn));

    // Send data
    ok(PQputCopyData(conn, "1,test1\n", 8) == 1,
       "PQputCopyData should succeed");
    ok(PQputCopyData(conn, "2,test2\n", 8) == 1,
       "PQputCopyData should succeed");
    ok(PQputCopyEnd(conn, NULL) == 1,
       "PQputCopyEnd should succeed");

    PQclear(res);
    res = PQgetResult(conn);

    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "COPY FREEZE should succeed after proper setup: %s",
       PQresultErrorMessage(res));
    PQclear(res);

    // Consume any remaining results
    while ((res = PQgetResult(conn)) != NULL) {
        PQclear(res);
    }

    // Commit transaction
    res = PQexec(conn, "COMMIT");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "COMMIT should succeed: %s", PQerrorMessage(conn));
    PQclear(res);
}

/**
 * @brief Test 3: Verify data was inserted correctly
 *
 * @param conn The PostgreSQL connection
 */
void testDataVerification(PGconn* conn) {
    diag("Test: Verify data was inserted correctly");

    PGresult* res = PQexec(conn, "SELECT * FROM copy_freeze_test ORDER BY id");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK,
       "SELECT should succeed: %s", PQerrorMessage(conn));

    int rows = PQntuples(res);
    ok(rows == 2, "Should have 2 rows, got %d", rows);

    bool row1_ok = (rows >= 1) && (strcmp(PQgetvalue(res, 0, 0), "1") == 0) &&
                   (strcmp(PQgetvalue(res, 0, 1), "test1") == 0);
    ok(row1_ok, "Row 1 should be (1, test1)");

    bool row2_ok = (rows >= 2) && (strcmp(PQgetvalue(res, 1, 0), "2") == 0) &&
                   (strcmp(PQgetvalue(res, 1, 1), "test2") == 0);
    ok(row2_ok, "Row 2 should be (2, test2)");
    PQclear(res);
}

/**
 * @brief Test 4: Multiple COPY errors in sequence
 *
 * This test verifies that the session can recover from multiple consecutive
 * COPY errors.
 *
 * @param conn The PostgreSQL connection
 */
void testMultipleCopyErrors(PGconn* conn) {
    diag("Test: Multiple consecutive COPY errors");

    // First COPY error
    PGresult* res = PQexec(conn, "COPY copy_freeze_test FROM stdin CSV FREEZE");
    ExecStatusType status = PQresultStatus(res);

    if (status == PGRES_COPY_IN) {
        PQputCopyEnd(conn, NULL);
        PQclear(res);
        res = PQgetResult(conn);
    }
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR,
       "First COPY FREEZE should fail: %s", PQresultErrorMessage(res));
    PQclear(res);
    while ((res = PQgetResult(conn)) != NULL) PQclear(res);

    // Second COPY error
    res = PQexec(conn, "COPY copy_freeze_test FROM stdin CSV FREEZE");
    status = PQresultStatus(res);

    if (status == PGRES_COPY_IN) {
        PQputCopyEnd(conn, NULL);
        PQclear(res);
        res = PQgetResult(conn);
    }
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR,
       "Second COPY FREEZE should fail: %s", PQresultErrorMessage(res));
    PQclear(res);
    while ((res = PQgetResult(conn)) != NULL) PQclear(res);

    // Verify subsequent normal query works
    res = PQexec(conn, "SELECT 1");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK,
       "SELECT should work after multiple COPY errors: %s", PQerrorMessage(conn));
    PQclear(res);
}

/**
 * @brief Test 5: COPY error followed by successful COPY
 *
 * This test verifies that after a COPY error, a properly executed COPY
 * command can succeed.
 *
 * @param conn The PostgreSQL connection
 */
void testCopyErrorThenSuccess(PGconn* conn) {
    diag("Test: COPY error followed by successful COPY");

    // Truncate table first
    PGresult* res = PQexec(conn, "TRUNCATE copy_freeze_test");
    PQclear(res);

    // First COPY - will fail (no transaction/truncate in same transaction)
    res = PQexec(conn, "COPY copy_freeze_test FROM stdin CSV FREEZE");
    ExecStatusType status = PQresultStatus(res);

    if (status == PGRES_COPY_IN) {
        PQputCopyEnd(conn, NULL);
        PQclear(res);
        res = PQgetResult(conn);
    }
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR,
       "First COPY FREEZE should fail: %s", PQresultErrorMessage(res));
    PQclear(res);
    while ((res = PQgetResult(conn)) != NULL) PQclear(res);

    // Now do it properly
    res = PQexec(conn, "BEGIN");
    PQclear(res);
    res = PQexec(conn, "TRUNCATE copy_freeze_test");
    PQclear(res);

    res = PQexec(conn, "COPY copy_freeze_test FROM stdin CSV");
    if (PQresultStatus(res) == PGRES_COPY_IN) {
        PQputCopyData(conn, "3,test3\n", 7);
        PQputCopyEnd(conn, NULL);
        PQclear(res);
        res = PQgetResult(conn);
    }
    ok(PQresultStatus(res) == PGRES_COMMAND_OK,
       "Regular COPY should succeed after COPY FREEZE error: %s",
       PQresultErrorMessage(res));
    PQclear(res);
    while ((res = PQgetResult(conn)) != NULL) PQclear(res);

    res = PQexec(conn, "COMMIT");
    PQclear(res);

    // Verify data
    res = PQexec(conn, "SELECT COUNT(*) FROM copy_freeze_test");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK &&
       PQntuples(res) > 0 &&
       atoi(PQgetvalue(res, 0, 0)) == 1,
       "Should have 1 row after successful COPY, got %s",
       PQgetvalue(res, 0, 0));
    PQclear(res);
}

/**
 * @brief Run all tests
 */
void runTests(PGconn* conn) {
    // Setup
    if (!setupTestTable(conn)) {
        BAIL_OUT("Failed to setup test table");
        return;
    }

    // Run test functions
    testCopyFreezeFailsImmediately(conn);
    testCopyFreezeSucceedsWithProperSetup(conn);
    testDataVerification(conn);
    testMultipleCopyErrors(conn);
    testCopyErrorThenSuccess(conn);

    // Cleanup
    cleanupTestTable(conn);
}

int main(int argc, char** argv) {
    // Total tests:
    // testCopyFreezeFailsImmediately: 5 tests (COPY fail, BEGIN, TRUNCATE, SAVEPOINT, COMMIT)
    // testCopyFreezeSucceedsWithProperSetup: 8 tests (BEGIN, TRUNCATE, COPY_IN, 3x data, result, COMMIT)
    // testDataVerification: 4 tests (SELECT, row count, 2x row data)
    // testMultipleCopyErrors: 3 tests (2x error, SELECT)
    // testCopyErrorThenSuccess: 3 tests (error, success, count)
    // Total: 23 tests
    plan(23);

    if (cl.getEnv()) {
        return exit_status();
    }

    // Create connection
    PGConnPtr conn = createNewConnection(false);
    if (!conn) {
        BAIL_OUT("Failed to connect to ProxySQL");
        return exit_status();
    }

    diag("Connected to ProxySQL via port %d", cl.pgsql_port);

    // Run tests
    runTests(conn.get());

    return exit_status();
}
