/**
 * @file pgsql-unsupported_feature_test-t.cpp
 * @brief Ensures that ProxySQL does not crash and maintains the connection/session integrity when unsupported queries are executed.
 * Currently validates:
 * 1) Prepare Statement
 * 2) COPY
 */

#include <string>
#include <sstream>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

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

void check_transaction_state(PGconn* conn) {
    PGresult* res;

    // Check if the transaction is still active
    res = PQexec(conn, "SELECT 1");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK && PQtransactionStatus(conn) == PQTRANS_INTRANS, 
        "Transaction state was not affected by the error. %s", PQerrorMessage(conn));
    PQclear(res);
}

void check_prepared_statement_binary(PGconn* conn) {
    PGresult* res;
    const char* paramValues[1] = { "1" };

    // Start a transaction
    res = PQexec(conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        BAIL_OUT("Could not start transaction. %s", PQerrorMessage(conn));
    }
    PQclear(res);

    // Test: Prepare a statement (using binary mode)
    res = PQprepare(conn, "myplan", "SELECT $1::int", 1, NULL);
    ok(PQresultStatus(res) != PGRES_COMMAND_OK, "Prepare statement failed. %s", PQerrorMessage(conn));
    PQclear(res);

    // Execute the prepared statement using binary protocol
    res = PQexecPrepared(conn, "myplan", 1, paramValues, NULL, NULL, 1); // Binary result format (1)
    ok(PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK, "Prepare statements are not supported for PostgreSQL: %s", PQerrorMessage(conn));
    PQclear(res);

    // Check if the transaction state is still active
    check_transaction_state(conn);

    // End the transaction
    res = PQexec(conn, "ROLLBACK");
    PQclear(res);
}

void check_copy_binary(PGconn* conn) {
    PGresult* res;

    // Start a transaction
    res = PQexec(conn, "BEGIN");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        BAIL_OUT("Could not start transaction. %s", PQerrorMessage(conn));
    }
    PQclear(res);

    // Test: COPY binary format
    res = PQexec(conn, "COPY (SELECT 1) TO STDOUT (FORMAT BINARY)");
    ok(PQresultStatus(res) != PGRES_COPY_OUT, "COPY binary command failed to start. %s", PQerrorMessage(conn));
    PQclear(res);

    // Attempt to fetch data in binary mode, expect it to fail
    char buffer[256];
    int ret = PQgetCopyData(conn, (char**)&buffer, 1); // Binary mode (1)
    ok(ret == -2, "COPY in binary mode should have failed. %s", PQerrorMessage(conn));

    // Check if the transaction state is still active
    check_transaction_state(conn);

    // End the transaction
    res = PQexec(conn, "ROLLBACK");
    PQclear(res);
}

void execute_tests(bool with_ssl) {
    PGconn* conn = create_new_connection(with_ssl);

    if (conn == nullptr)
        return;

    // Test 1: Prepared Statement in binary mode
    check_prepared_statement_binary(conn);

    // Test 2: COPY in binary mode
    check_copy_binary(conn);

    // Close the connection

    PQfinish(conn);
}

int main(int argc, char** argv) {

    plan(7); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    execute_tests(false); // without SSL

    return exit_status();
}
