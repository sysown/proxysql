/**
 * @file pgsql-frontend_ssl_enforcement-t.cpp
 * @brief This test validates that ProxySQL correctly enforces SSL requirement for
 *        PostgreSQL frontend connections when use_ssl=1 is set in pgsql_users.
 *
 *        The test addresses the issue where setting use_ssl=1 didn't actually
 *        enforce TLS - clients could still connect without SSL.
 *
 *        Test scenarios:
 *        1. With use_ssl=1: connection without SSL should be rejected
 *        2. With use_ssl=1: connection with SSL should succeed
 *        3. With use_ssl=0: connection without SSL should succeed
 *        4. With use_ssl=0: connection with SSL should succeed
 */

#include <string>
#include <sstream>
#include <vector>

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

/**
 * @brief Creates a new PostgreSQL connection with specified SSL mode.
 *
 * @param conn_type Type of connection (ADMIN or BACKEND)
 * @param with_ssl Whether to use SSL for the connection
 * @return PGConnPtr Smart pointer to the connection
 */
PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl = false) {
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        // For expected failures, we still return the conn so caller can check
        return PGConnPtr(conn, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

/**
 * @brief Checks if a connection uses SSL.
 *
 * @param conn The connection to check
 * @return true if SSL is used, false otherwise
 */
bool is_connection_using_ssl(PGconn* conn) {
    return PQsslInUse(conn) == 1;
}

int main(int argc, char** argv) {

    // We have 6 test cases:
    // 1. Admin connection
    // 2. Set use_ssl=1 and load to runtime
    // 3. Connection without SSL should fail when use_ssl=1
    // 4. Connection with SSL should succeed when use_ssl=1
    // 5. Set use_ssl=0 and load to runtime
    // 6. Connection without SSL should succeed when use_ssl=0
    // 7. Connection with SSL should succeed when use_ssl=0
    plan(7);

    if (cl.getEnv())
        return exit_status();

    // ============================================
    // Test 1: Connect to ADMIN interface
    // ============================================
    auto admin = createNewConnection(ADMIN, false);
    ok(admin != nullptr && PQstatus(admin.get()) == CONNECTION_OK,
       "ADMIN connection created");

    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
        BAIL_OUT("Cannot proceed without admin connection");
        return exit_status();
    }

    // ============================================
    // Test 2: Set use_ssl=1 for the test user
    // ============================================
    {
        std::stringstream q;
        q << "UPDATE pgsql_users SET use_ssl=1 WHERE username='" << cl.pgsql_username << "';";
        PGresult* res = PQexec(admin.get(), q.str().c_str());
        bool update_ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);

        res = PQexec(admin.get(), "LOAD PGSQL USERS TO RUNTIME;");
        bool load_ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);

        ok(update_ok && load_ok, "Set use_ssl=1 and loaded to runtime");

        if (!update_ok || !load_ok) {
            BAIL_OUT("Failed to configure pgsql_users");
            return exit_status();
        }
    }

    // Give ProxySQL time to load the configuration
    usleep(100000); // 100ms

    // ============================================
    // Test 3: Connection WITHOUT SSL should FAIL when use_ssl=1
    // ============================================
    {
        auto conn = createNewConnection(BACKEND, false); // sslmode=disable
        bool conn_failed = (conn && PQstatus(conn.get()) != CONNECTION_OK);

        if (conn_failed) {
            ok(true, "Connection without SSL rejected when use_ssl=1 (as expected)");
            diag("Connection error: %s", PQerrorMessage(conn.get()));
        } else {
            ok(false, "Connection without SSL should be rejected when use_ssl=1, but it succeeded");
        }
    }

    // ============================================
    // Test 4: Connection WITH SSL should SUCCEED when use_ssl=1
    // ============================================
    {
        auto conn = createNewConnection(BACKEND, true); // sslmode=require
        bool conn_ok = (conn && PQstatus(conn.get()) == CONNECTION_OK);
        bool uses_ssl = conn_ok && is_connection_using_ssl(conn.get());

        if (conn_ok && uses_ssl) {
            ok(true, "Connection with SSL succeeded when use_ssl=1");
        } else {
            ok(false, "Connection with SSL should succeed when use_ssl=1");
            if (!conn_ok) {
                diag("Connection error: %s", PQerrorMessage(conn.get()));
            } else {
                diag("Connection succeeded but SSL not in use");
            }
        }
    }

    // ============================================
    // Test 5: Set use_ssl=0 for the test user
    // ============================================
    {
        std::stringstream q;
        q << "UPDATE pgsql_users SET use_ssl=0 WHERE username='" << cl.pgsql_username << "';";
        PGresult* res = PQexec(admin.get(), q.str().c_str());
        bool update_ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);

        res = PQexec(admin.get(), "LOAD PGSQL USERS TO RUNTIME;");
        bool load_ok = (PQresultStatus(res) == PGRES_COMMAND_OK);
        PQclear(res);

        ok(update_ok && load_ok, "Set use_ssl=0 and loaded to runtime");

        if (!update_ok || !load_ok) {
            BAIL_OUT("Failed to configure pgsql_users");
            return exit_status();
        }
    }

    // Give ProxySQL time to load the configuration
    usleep(100000); // 100ms

    // ============================================
    // Test 6: Connection WITHOUT SSL should SUCCEED when use_ssl=0
    // ============================================
    {
        auto conn = createNewConnection(BACKEND, false); // sslmode=disable
        bool conn_ok = (conn && PQstatus(conn.get()) == CONNECTION_OK);

        if (conn_ok) {
            ok(true, "Connection without SSL succeeded when use_ssl=0");
        } else {
            ok(false, "Connection without SSL should succeed when use_ssl=0");
            diag("Connection error: %s", PQerrorMessage(conn.get()));
        }
    }

    // ============================================
    // Test 7: Connection WITH SSL should also SUCCEED when use_ssl=0
    // (SSL is optional when use_ssl=0)
    // ============================================
    {
        auto conn = createNewConnection(BACKEND, true); // sslmode=require
        bool conn_ok = (conn && PQstatus(conn.get()) == CONNECTION_OK);
        bool uses_ssl = conn_ok && is_connection_using_ssl(conn.get());

        if (conn_ok && uses_ssl) {
            ok(true, "Connection with SSL succeeded when use_ssl=0 (SSL is optional)");
        } else {
            ok(false, "Connection with SSL should succeed when use_ssl=0");
            if (!conn_ok) {
                diag("Connection error: %s", PQerrorMessage(conn.get()));
            } else {
                diag("Connection succeeded but SSL not in use");
            }
        }
    }

    return exit_status();
}
