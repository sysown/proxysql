/**
 * @file pgsql-reg_test_4716_single_semicolon-t.cpp
 * @brief  This test aims to verify that ProxySQL handles a lone semicolon (;) input 
 * crashing. The expected behavior is for ProxySQL to either ignore the input or return an 
 * appropriate error message, rather than crashing or becoming unresponsive.
 */

#include <string>
#include <sstream>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

enum ConnType {
    ADMIN,
    BACKEND
};

PGconn* createNewConnection(ConnType conn_type, bool with_ssl) {
    std::stringstream ss;
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;
    

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        diag("Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return nullptr;
    }
    return conn;
}

int main(int argc, char** argv) {

    std::vector<const char*> queries = { ";", " ", "", ";  ", "  ;" };

    plan(queries.size() + 1); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    PGconn* conn = createNewConnection(ADMIN, false);

    if (conn == nullptr)
        return exit_status();

    PGresult* res = nullptr;

    for (const char* query : queries) {
        PGresult* res = PQexec(conn, query);

        ok(PQresultStatus(res) == PGRES_FATAL_ERROR,
            "Error. %s", PQerrorMessage(conn));
        PQclear(res);
    }

    res = PQexec(conn, "SELECT 1");
    ok(PQresultStatus(res) == PGRES_TUPLES_OK,
        "Query executed sucessfully. %s", PQerrorMessage(conn));
    PQclear(res);

    // Close the connection
    PQfinish(conn);

    return exit_status();
}
