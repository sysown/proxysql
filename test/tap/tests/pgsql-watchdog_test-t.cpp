/**
 * @file pgsql_watchdog_test-t.cpp
 * @brief Test ProxySQL watchdog heartbeat for PgSQL threads.
 * @details This test runs ProxySQL's internal test commands:
 *  - PROXYSQLTEST 55 1 → PgSQL watchdog test
 */
#include <string>
#include <sstream>
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

PGConnPtr createNewConnection(ConnType conn_type, const std::string& parameters = "", bool with_ssl = false) {

    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    if (parameters.empty() == false) {
        ss << " " << parameters;
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s\n", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

bool run_watchdog_test(PGconn* conn, int test_arg, const char* label) {
	char query[64];
	snprintf(query, sizeof(query), "PROXYSQLTEST 55 %d", test_arg);

	diag("Running %s watchdog test...", label);

	PGresult* res = PQexec(conn, query);
	if (!res) {
		diag("Null result from libpq: %s", PQerrorMessage(conn));
		ok(false, "Watchdog test %s failed to execute", label);
		return false;
	}

	ExecStatusType status = PQresultStatus(res);
	if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK) {
		std::string msg = PQresultErrorMessage(res);
		if (msg.find("Invalid test") != std::string::npos) {
			ok(true, "ProxySQL is not compiled in Debug mode. Skipping %s watchdog test", label);
		}
		else {
			diag("Error running %s test: %s", label, msg.c_str());
			ok(false, "Watchdog test %s failed", label);
		}
		PQclear(res);
		return false;
	}

	ok(true, "%s watchdog test executed successfully", label);
	PQclear(res);
	return true;
}

int main() {
	if (cl.getEnv()) {
		diag("Failed to get required environment variables");
		return -1;
	}

	plan(1);  // One test for MySQL

	auto admin_conn = createNewConnection(ConnType::ADMIN, "", false);
	
    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

	run_watchdog_test(admin_conn.get(), 1, "PostgreSQL");

	return exit_status();
}
