/**
 * @file pgsql-proxysql_cmd_test-t.cpp
 * @brief Test PAUSE/RESUME/STOP/START command sequences and validate backend connectivity changes.
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
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

bool executeAdminCommand(PGConnPtr& conn, const std::string& command) {
    PGresult* res = PQexec(conn.get(), command.c_str());
    ConnStatusType status = PQstatus(conn.get());
    ExecStatusType result_status = PQresultStatus(res);

    bool success = (result_status == PGRES_COMMAND_OK || result_status == PGRES_TUPLES_OK);

    if (!success) {
        diag("Command failed: %s - %s", command.c_str(), PQerrorMessage(conn.get()));
    }

    PQclear(res);
    return success;
}

bool canConnectToBackend() {
    auto conn = createNewConnection(BACKEND);
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        return false;
    }

    // Test if we can execute a simple query
    PGresult* res = PQexec(conn.get(), "SELECT 1");
    bool query_ok = (PQresultStatus(res) == PGRES_TUPLES_OK);
    PQclear(res);

    return query_ok;
}

void waitForProxySQLState(int seconds) {
    diag("Waiting %d seconds for ProxySQL state change", seconds);
    sleep(seconds);
}

void testPauseResumeSequence() {
    diag("Testing PROXYSQL PAUSE/RESUME sequence");

    auto admin_conn = createNewConnection(ADMIN);
    if (!admin_conn) {
        ok(false, "Connect to ProxySQL admin");
        return;
    }

    // First PAUSE should succeed
    bool result = executeAdminCommand(admin_conn, "PROXYSQL PAUSE");
    ok(result, "First PROXYSQL PAUSE command should succeed");

    waitForProxySQLState(3);

    // Second PAUSE should fail (already paused)
    result = executeAdminCommand(admin_conn, "PROXYSQL PAUSE");
    ok(!result, "Second PROXYSQL PAUSE should fail (already paused)");

    // New connection should be rejected
    bool backend_connectable = canConnectToBackend();
    ok(!backend_connectable, "New connection should be rejected after PROXYSQL PAUSE");

    // First RESUME should succeed
    result = executeAdminCommand(admin_conn, "PROXYSQL RESUME");
    ok(result, "First PROXYSQL RESUME command should succeed");

    waitForProxySQLState(3);

    // Second RESUME should fail (already running)
    result = executeAdminCommand(admin_conn, "PROXYSQL RESUME");
    ok(!result, "Second PROXYSQL RESUME should fail (already running)");

    // New connection should succeed
    backend_connectable = canConnectToBackend();
    ok(backend_connectable, "New connection should succeed after PROXYSQL RESUME");
}

void testStopStartSequence() {
    diag("Testing PROXYSQL STOP/START sequence");

    auto admin_conn = createNewConnection(ADMIN);
    if (!admin_conn) {
        ok(false, "Connect to ProxySQL admin");
        return;
    }

    // First STOP should succeed
    bool result = executeAdminCommand(admin_conn, "PROXYSQL STOP");
    ok(result, "First PROXYSQL STOP command should succeed");

    waitForProxySQLState(5); // Give more time for stop

    // Try to execute another command - should fail as ProxySQL is stopping/stopped
    result = executeAdminCommand(admin_conn, "SELECT 1");

    // Note: The connection might be closed during STOP, so we need to handle this
    if (PQstatus(admin_conn.get()) != CONNECTION_OK) {
        diag("Admin connection closed as expected during PROXYSQL STOP");
        // Reconnect for the rest of the test
        admin_conn = createNewConnection(ADMIN);
        if (!admin_conn) {
            ok(false, "Reconnect after PROXYSQL STOP failed");
            return;
        }
    }

    // Second STOP should fail (already stopping/stopped)
    result = executeAdminCommand(admin_conn, "PROXYSQL STOP");
    ok(!result, "Second PROXYSQL STOP should fail (already stopping/stopped)");

    // New connection should be rejected
    bool backend_connectable = canConnectToBackend();
    ok(!backend_connectable, "New connection should be rejected after PROXYSQL STOP");

    // First START should succeed
    result = executeAdminCommand(admin_conn, "PROXYSQL START");
    ok(result, "First PROXYSQL START command should succeed");

    waitForProxySQLState(5); // Give more time for start

    // Second START should fail (already starting/started)
    result = executeAdminCommand(admin_conn, "PROXYSQL START");
    ok(!result, "Second PROXYSQL START should fail (already starting/started)");

    // New connection should succeed
    backend_connectable = canConnectToBackend();
    ok(backend_connectable, "New connection should succeed after PROXYSQL START");
}

int main(int argc, char** argv) {
    plan(12);

    if (cl.getEnv())
        return exit_status();

    testPauseResumeSequence();
    testStopStartSequence();

    return exit_status();
}
