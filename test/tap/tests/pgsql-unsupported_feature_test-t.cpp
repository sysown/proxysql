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
#include "pgsql_native_tier.h"

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

void check_copy_stdin_via_extended_query(PGconn* conn) {
    PGresult* res = PQprepare(conn,
        "copy_stmt",
        "COPY mytable FROM STDIN",
        0,
        NULL);

    ExecStatusType status = PQresultStatus(res);

    /* Check that it failed */
    ok(status == PGRES_FATAL_ERROR, "PQprepare fails for COPY FROM STDIN");

    const char* sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);

    ok(sqlstate && strcmp(sqlstate, "0A000") == 0,
        "SQLSTATE is 0A000 (feature_not_supported)");

    PQclear(res);
}

bool prepare_backend_protocol() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
       << " user=" << cl.admin_username << " password=" << cl.admin_password
       << " dbname=postgres sslmode=disable";
    PGconn* admin = PQconnectdb(ss.str().c_str());
    if (PQstatus(admin) != CONNECTION_OK)
        BAIL_OUT("Cannot connect to admin: %s", PQerrorMessage(admin));
    const bool native = pgsql_native_active(admin);
    auto command = [admin](const char* sql) {
        PGresult* result = PQexec(admin, sql);
        const bool success = PQresultStatus(result) == PGRES_COMMAND_OK;
        if (!success) diag("Admin command failed: %s: %s", sql, PQerrorMessage(admin));
        PQclear(result);
        return success;
    };
    // LOAD VARIABLES changes how new backends are created, not existing pooled
    // backends. Preserve all configured statuses while discarding the old pool.
    if (!command("CREATE TEMP TABLE listen_saved_servers AS SELECT hostgroup_id,hostname,port,status FROM pgsql_servers")) {
        PQfinish(admin);
        BAIL_OUT("Cannot save backend statuses before clearing the pool");
    }
    bool cleared = command("UPDATE pgsql_servers SET status='OFFLINE_HARD'") &&
        command("LOAD PGSQL SERVERS TO RUNTIME");
    if (cleared) {
        PGresult* result = PQexec(admin,
            "SELECT COALESCE(SUM(ConnFree),0) FROM stats_pgsql_connection_pool");
        cleared = PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) == 1 &&
            strcmp(PQgetvalue(result, 0, 0), "0") == 0;
        PQclear(result);
    }
    // Restore even if clearing failed, but never load an unrestored configuration.
    auto restore = [&command]() {
        return command("UPDATE pgsql_servers SET status=(SELECT status FROM listen_saved_servers s "
            "WHERE s.hostgroup_id=pgsql_servers.hostgroup_id AND s.hostname=pgsql_servers.hostname AND s.port=pgsql_servers.port)") &&
            command("LOAD PGSQL SERVERS TO RUNTIME");
    };
    bool restored = restore();
    if (!restored) {
        diag("Retrying restoration of PostgreSQL server statuses");
        restored = restore();
    }
    if (restored) command("DROP TABLE listen_saved_servers");
    if (!cleared || !restored) {
        PQfinish(admin);
        BAIL_OUT("Cannot clear old backend connections and restore server statuses");
    }
    PQfinish(admin);
    return native;
}

void check_listening_channel(PGconn* conn) {
    PGresult* res = PQexec(conn, "SELECT * FROM pg_listening_channels()");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1 &&
        strcmp(PQgetvalue(res, 0, 0), "mychannel") == 0,
        "Native LISTEN registers the channel on the session's backend");
    PQclear(res);
}

void check_listen_via_simple_and_extended_query(PGconn* conn, bool native) {

    PGresult* res = PQexec(conn, "LISTEN mychannel");
    if (native) {
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, "PQexec supports native LISTEN");
        PQclear(res);
        check_listening_channel(conn);
        res = PQexec(conn, "UNLISTEN *");
        if (PQresultStatus(res) != PGRES_COMMAND_OK)
            BAIL_OUT("Cannot clear simple LISTEN: %s", PQerrorMessage(conn));
        PQclear(res);
        res = PQprepare(conn, "listen_stmt", "LISTEN mychannel", 0, NULL);
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, "PQprepare supports native LISTEN");
        PQclear(res);
        res = PQexecPrepared(conn, "listen_stmt", 0, NULL, NULL, NULL, 0);
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Prepared native LISTEN executes successfully");
        PQclear(res);
        check_listening_channel(conn);
        res = PQexec(conn, "UNLISTEN *");
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Native UNLISTEN succeeds after prepared LISTEN");
        PQclear(res);
        return;
    }
    ExecStatusType status = PQresultStatus(res);
    /* Check that it failed */
    ok(status == PGRES_FATAL_ERROR, "PQexec fails for LISTEN");
    const char* sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
    ok(sqlstate && strcmp(sqlstate, "0A000") == 0,
        "SQLSTATE is 0A000 (feature_not_supported)");
    PQclear(res);
    res = PQprepare(conn,
        "listen_stmt",
        "LISTEN mychannel",
        0,
        NULL);
    status = PQresultStatus(res);
    /* Check that it failed */
    ok(status == PGRES_FATAL_ERROR, "PQprepare fails for LISTEN");
    sqlstate = PQresultErrorField(res, PG_DIAG_SQLSTATE);
    ok(sqlstate && strcmp(sqlstate, "0A000") == 0,
        "SQLSTATE is 0A000 (feature_not_supported)");
	PQclear(res);
}

void execute_tests(bool with_ssl, bool native) {
    PGconn* conn = create_new_connection(with_ssl);

    if (conn == nullptr)
        return;

    /* Now, supported features 
     * Test 1: Prepared Statement in binary mode
     * check_prepared_statement_binary(conn);
     *
     *  Test 2: COPY in binary mode
     * check_copy_binary(conn); 
     */

	// Test 3: COPY FROM STDIN via extended query
	check_copy_stdin_via_extended_query(conn);

	// Test 4: LISTEN via simple and extended query
	check_listen_via_simple_and_extended_query(conn, native);

    // Close the connection
    PQfinish(conn);
}

int main(int argc, char** argv) {
    if (cl.getEnv())
        return exit_status();

    const bool native = prepare_backend_protocol();
    plan(native ? 9 : 7);
    execute_tests(false, native); // without SSL

    return exit_status();
}
