/**
 * @file pgsql-basic_tests-t.cpp
 * @brief This test conducts a thorough validation of various PostgreSQL database operations.
 * It begins by establishing a valid database connection and confirming successful connectivity.
 * Subsequently, the test performs a series of Data Definition Language (DDL) and Data Manipulation Language (DML) operations,
 * which include table creation, data insertion, selection, updates, deletions, and transactions.
 */

#include <string>
#include <sstream>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"


#define PQEXEC(conn, query) ({PGresult* res = PQexec(conn, query); \
                              ExecStatusType status = PQresultStatus(res); \
                              if (status != PGRES_COMMAND_OK && \
                                  status != PGRES_TUPLES_OK) { \
                                  fprintf(stderr, "File %s, line %d, status %d, %s\n", \
					              __FILE__, __LINE__, status, PQresultErrorMessage(res)); \
                              } \
							  res; \
                              })

#define PQSENDQUERY(conn,query) ({int send_status = PQsendQuery(conn,query); \
                                 if (send_status != 1) { \
                                     fprintf(stderr, "File %s, line %d, status %d, %s\n", \
					              __FILE__, __LINE__, status, PQerrorMessage(conn)); \
                                 } \
                                 send_status; \
                                 })


CommandLine cl;

PGconn* create_new_connection(bool with_ssl) {
    std::stringstream ss;

    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port;
    ss << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password;

    if (with_ssl) {
        ss << " sslmode=require";
    } else {
        ss << " sslmode=disable";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    const bool res = (conn && PQstatus(conn) == CONNECTION_OK);
    ok(res, "Connection created successfully. %s", PQerrorMessage(conn));

    if (res) return conn;

    PQfinish(conn);
    return nullptr;
}

// Function to set up the test environment
void setup_database(PGconn* conn) {
    PGresult* res;

    res = PQEXEC(conn, "DROP TABLE IF EXISTS test_table");
    PQclear(res);

    res = PQEXEC(conn, "CREATE TABLE test_table (id SERIAL PRIMARY KEY, value TEXT)");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Created test_table");
    PQclear(res);

    res = PQEXEC(conn, "INSERT INTO test_table (value) VALUES ('test1'), ('test2'), ('test3')");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Inserted initial records into test_table");
    PQclear(res);
}

void test_simple_query(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "SELECT 1");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        ok(1, "Simple SELECT query executed successfully");
        int nFields = PQnfields(res);
        int nRows = PQntuples(res);
        ok(nFields == 1, "Returned one field");
        ok(nRows == 1, "Returned one row");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "1") == 0, "Result is 1");
    } else {
        ok(0, "Simple SELECT query failed");
    }
    PQclear(res);
}

void test_insert_query(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "INSERT INTO test_table (value) VALUES ('test4')");
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(1, "INSERT query executed successfully");
        ok(strcmp(PQcmdTuples(res), "1") == 0, "One row inserted");
    } else {
        ok(0, "INSERT query failed");
    }
    PQclear(res);

    // Verify insertion
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value = 'test4'");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Inserted row is present");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "test4") == 0, "Inserted value is correct");
    } else {
        ok(0, "Failed to verify inserted row");
    }
    PQclear(res);
}

void test_update_query(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "UPDATE test_table SET value = 'updated' WHERE value = 'test2'");
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(1, "UPDATE query executed successfully");
        ok(strcmp(PQcmdTuples(res), "1") == 0, "One row updated");
    } else {
        ok(0, "UPDATE query failed");
    }
    PQclear(res);

    // Verify update
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value = 'updated'");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Updated row is present");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "updated") == 0, "Updated value is correct");
    } else {
        ok(0, "Failed to verify updated row");
    }
    PQclear(res);
}

void test_delete_query(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "DELETE FROM test_table WHERE value = 'test3'");
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(1, "DELETE query executed successfully");
        ok(strcmp(PQcmdTuples(res), "1") == 0, "One row deleted");
    } else {
        ok(0, "DELETE query failed");
    }
    PQclear(res);

    // Verify deletion
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value = 'test3'");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 0, "Deleted row is no longer present");
    } else {
        ok(0, "Failed to verify deleted row");
    }
    PQclear(res);
}

void test_invalid_query(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "SELECT * FROM non_existent_table");
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR, "Query on non-existent table failed as expected");
    PQclear(res);
}

void test_transaction_commit(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "BEGIN");
    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection in Transaction state");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "BEGIN transaction");

    res = PQEXEC(conn, "INSERT INTO test_table (value) VALUES ('transaction commit')");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT in transaction");
    PQclear(res);

    res = PQEXEC(conn, "COMMIT");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "COMMIT transaction");
    PQclear(res);
    ok(PQtransactionStatus(conn) == PQTRANS_IDLE, "Connection in Idle state");

    // Verify commit
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value = 'transaction commit'");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Committed row is present");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "transaction commit") == 0, "Committed value is correct");
    } else {
        ok(0, "Failed to verify committed row");
    }
    PQclear(res);
}

void test_transaction_rollback(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "BEGIN");
    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection in Transaction state");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "BEGIN transaction");

    res = PQEXEC(conn, "INSERT INTO test_table (value) VALUES ('transaction rollback')");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT in transaction");
    PQclear(res);

    res = PQEXEC(conn, "ROLLBACK");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "ROLLBACK transaction");
    PQclear(res);
    ok(PQtransactionStatus(conn) == PQTRANS_IDLE, "Connection in Idle state");

    // Verify rollback
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value = 'transaction rollback'");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 0, "Rolled back row is not present");
    } else {
        ok(0, "Failed to verify rolled back row");
    }
    PQclear(res);
}

void test_transaction_error(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "BEGIN");
    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Connection in Transaction state");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "BEGIN transaction");

    res = PQEXEC(conn, "SELECT 1/0");
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR, "Error result returned");
    PQclear(res);
    ok(PQtransactionStatus(conn) == PQTRANS_INERROR, "Connection in Error Transaction state");

    res = PQEXEC(conn, "ROLLBACK");
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "ROLLBACK transaction");
    PQclear(res);
    ok(PQtransactionStatus(conn) == PQTRANS_IDLE, "Connection in Idle state");

    // Verify rollback
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value = 'transaction rollback'");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 0, "Rolled back row is not present");
    } else {
        ok(0, "Failed to verify rolled back row");
    }
    PQclear(res);
}

void test_null_value(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "INSERT INTO test_table (value) VALUES (NULL)");
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(1, "INSERT NULL value executed successfully");
        ok(strcmp(PQcmdTuples(res), "1") == 0, "One row inserted with NULL value");
    } else {
        ok(0, "INSERT NULL value failed");
    }
    PQclear(res);

    // Verify NULL insertion
    res = PQEXEC(conn, "SELECT value FROM test_table WHERE value IS NULL");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Inserted NULL value is present");
    } else {
        ok(0, "Failed to verify inserted NULL value");
    }
    PQclear(res);
}

void test_constraint_violation(PGconn* conn) {
    PGresult* res = PQEXEC(conn, "INSERT INTO test_table (id, value) VALUES (1, 'duplicate id')");
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR, "INSERT with duplicate ID failed as expected");
    PQclear(res);
}

void test_multi_statement_transaction(PGconn* conn) {
    PGresult* res;
    int status;

    // Execute multi-statement transaction
    status = PQsendQuery(conn, "BEGIN; "
        "INSERT INTO test_table (value) VALUES ('multi statement'); "
        "UPDATE test_table SET value = 'multi statement updated' WHERE value = 'multi statement'; "
        "COMMIT;");
    ok(status == 1, "Multi-statement transaction sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check result of BEGIN
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "BEGIN executed successfully");
    PQclear(res);

    // Check result of INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT executed successfully");
    PQclear(res);

    // Check result of UPDATE
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "UPDATE executed successfully");
    PQclear(res);

    // Check result of COMMIT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "COMMIT executed successfully");
    PQclear(res);

    res = PQgetResult(conn);
    ok(PQtransactionStatus(conn) == PQTRANS_IDLE, "Connection in Idle state");

    // Verify the results
    status = PQsendQuery(conn, "SELECT value FROM test_table WHERE value = 'multi statement updated'");
    ok(status == 1, "Verification query sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Multi-statement transaction committed correctly");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "multi statement updated") == 0, "Multi-statement transaction result is correct");
    } else {
        ok(0, "Failed to verify multi-statement transaction");
    }
    PQclear(res);
    PQgetResult(conn);
}

void test_multi_statement_transaction_with_error(PGconn* conn) {
    PGresult* res;
    int status;

    // Execute multi-statement transaction with an error
    status = PQSENDQUERY(conn, "BEGIN; "
        "INSERT INTO test_table (value) VALUES ('multi statement error'); "
        "UPDATE test_table SET value = 'multi statement error updated' WHERE value = 'multi statement error'; "
        "INSERT INTO test_table (non_existent_column) VALUES ('error'); "
        "COMMIT;");
    ok(status == 1, "Multi-statement transaction with error sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check result of BEGIN
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "BEGIN executed successfully");
    PQclear(res);

    // Check result of INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT executed successfully");
    PQclear(res);

    // Check result of UPDATE
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "UPDATE executed successfully");
    PQclear(res);

    // Check result of erroneous INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR, "Erroneous INSERT failed as expected");
    PQclear(res);

    PQgetResult(conn);
    // Ensure the transaction is in error state
    ok(PQtransactionStatus(conn) == PQTRANS_INERROR, "Connection in Error Transaction state");

    // Rollback the transaction
    status = PQsendQuery(conn, "ROLLBACK");
    ok(status == 1, "ROLLBACK sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "ROLLBACK executed successfully");
    PQclear(res);

    PQgetResult(conn);

    ok(PQtransactionStatus(conn) == PQTRANS_IDLE, "Connection in Idle state");

    // Verify the results
    status = PQsendQuery(conn, "SELECT value FROM test_table WHERE value = 'multi statement error' OR value = 'multi statement error updated'");
    ok(status == 1, "Verification query sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 0, "Multi-statement transaction with error rolled back correctly");
    } else {
        ok(0, "Failed to verify rollback of multi-statement transaction with error");
    }
    PQclear(res);
    PQgetResult(conn);
}

void test_multi_statement_select_insert(PGconn* conn) {
    PGresult* res;
    int status;

    // Execute multi-statement SELECT and INSERT
    status = PQsendQuery(conn, "SELECT value FROM test_table WHERE id = 1; "
        "INSERT INTO test_table (value) VALUES ('multi statement select insert');");
    ok(status == 1, "Multi-statement SELECT and INSERT sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check result of SELECT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_TUPLES_OK, "SELECT executed successfully");
    PQclear(res);

    // Check result of INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT executed successfully");
    PQclear(res);

    PQgetResult(conn);

    // Verify the results
    status = PQsendQuery(conn, "SELECT value FROM test_table WHERE value = 'multi statement select insert'");
    ok(status == 1, "Verification query sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Multi-statement SELECT and INSERT committed correctly");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "multi statement select insert") == 0, "Multi-statement SELECT and INSERT result is correct");
    } else {
        ok(0, "Failed to verify multi-statement SELECT and INSERT");
    }
    PQclear(res);
    PQgetResult(conn);
}

void test_multi_statement_delete_update(PGconn* conn) {
    PGresult* res;
    int status;

    // Execute multi-statement DELETE and UPDATE
    status = PQsendQuery(conn, "DELETE FROM test_table WHERE value = 'test1'; "
        "UPDATE test_table SET value = 'multi statement delete update' WHERE value = 'test4';");
    ok(status == 1, "Multi-statement DELETE and UPDATE sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check result of DELETE
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "DELETE executed successfully");
    PQclear(res);

    // Check result of UPDATE
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "UPDATE executed successfully");
    PQclear(res);

    PQgetResult(conn);

    // Verify the results
    status = PQsendQuery(conn, "SELECT value FROM test_table WHERE value = 'multi statement delete update'");
    ok(status == 1, "Verification query sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Multi-statement DELETE and UPDATE committed correctly");
        char* result = PQgetvalue(res, 0, 0);
        ok(strcmp(result, "multi statement delete update") == 0, "Multi-statement DELETE and UPDATE result is correct");
    } else {
        ok(0, "Failed to verify multi-statement DELETE and UPDATE");
    }
    PQclear(res);
    PQgetResult(conn);
}

void test_multi_statement_with_error(PGconn* conn) {
    PGresult* res;
    int status;

    // Execute multi-statement with an error
    status = PQsendQuery(conn, "INSERT INTO test_table (value) VALUES ('multi statement error'); "
        "UPDATE test_table SET value = 'multi statement error updated' WHERE value = 'multi statement error'; "
        "INSERT INTO test_table (non_existent_column) VALUES ('error');");
    ok(status == 1, "Multi-statement with error sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check result of INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT executed successfully");
    PQclear(res);

    // Check result of UPDATE
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "UPDATE executed successfully");
    PQclear(res);

    // Check result of erroneous INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_FATAL_ERROR, "Erroneous INSERT failed as expected");
    PQclear(res);

    PQgetResult(conn);
    // Verify the results
    status = PQsendQuery(conn, "SELECT value FROM test_table WHERE value = 'multi statement error' OR value = 'multi statement error updated'");
    ok(status == 1, "Verification query sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 0, "No rows are inserted or updated");
    } else {
        ok(0, "Failed to verify rows from multi-statement with error");
    }
    PQclear(res);
    PQgetResult(conn);
}

void test_multi_statement_insert_select_select(PGconn* conn) {
    PGresult* res;
    int status;

    // Execute multi-statement INSERT, SELECT, and SELECT
    status = PQsendQuery(conn, "INSERT INTO test_table (value) VALUES ('multi statement select1'), ('multi statement select2'); "
        "SELECT value FROM test_table WHERE value = 'multi statement select1'; "
        "SELECT value FROM test_table WHERE value = 'multi statement select2';");
    ok(status == 1, "Multi-statement INSERT and SELECTs sent");
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check result of the INSERT
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "INSERT executed successfully");
    PQclear(res);

    // Check result of the first SELECT
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "First SELECT executed successfully");
        if (nRows > 0) {
            char* result = PQgetvalue(res, 0, 0);
            ok(strcmp(result, "multi statement select1") == 0, "First SELECT result is correct");
        }
    } else {
        ok(0, "First SELECT failed");
    }
    PQclear(res);

    // Check result of the second SELECT
    res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int nRows = PQntuples(res);
        ok(nRows == 1, "Second SELECT executed successfully");
        if (nRows > 0) {
            char* result = PQgetvalue(res, 0, 0);
            ok(strcmp(result, "multi statement select2") == 0, "Second SELECT result is correct");
        }
    } else {
        ok(0, "Second SELECT failed");
    }
    PQclear(res);
    PQgetResult(conn);
}

void teardown_database(PGconn* conn) {
    PGresult* res;

    res = PQEXEC(conn, "DROP TABLE IF EXISTS test_table");
    PQclear(res);
}

void test_invalid_connection(bool with_ssl) {

    std::stringstream ss;

    ss << "host=invalid_host port=invalid_port dbname=invalid_db user=invalid_user password=invalid_password";

    if (with_ssl) {
        ss << " sslmode=require";
    } else {
        ss << " sslmode=disable";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    ok(PQstatus(conn) == CONNECTION_BAD, "Connection failed with invalid parameters");
    PQfinish(conn);
}

void execute_tests(bool with_ssl) {
    PGconn* conn = create_new_connection(with_ssl);

    if (conn == nullptr)
        return;

    setup_database(conn);
    test_simple_query(conn);
    test_insert_query(conn);
    test_update_query(conn);
    test_delete_query(conn);
    test_invalid_query(conn);
    test_transaction_commit(conn);
    test_transaction_rollback(conn);
    test_transaction_error(conn);
    test_null_value(conn);
    test_constraint_violation(conn);
    test_multi_statement_transaction(conn);
    test_multi_statement_transaction_with_error(conn);
    test_multi_statement_select_insert(conn);
    test_multi_statement_delete_update(conn);
    test_multi_statement_with_error(conn);
    test_multi_statement_insert_select_select(conn);
    teardown_database(conn);
    test_invalid_connection(with_ssl);

    PQfinish(conn);
}

int main(int argc, char** argv) {

    plan(176); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    execute_tests(false); // without SSL
    execute_tests(true); // with SSL

    return exit_status();
}
