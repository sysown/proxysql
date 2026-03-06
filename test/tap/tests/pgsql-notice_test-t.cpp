/**
 * @file pgsql-notice_test-t.cpp
 * @brief This TAP test validates handling of PostgreSQL notices in ProxySQL. 
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "noise_utils.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl) {
    
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
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

bool executeQuery(PGconn* conn, const char* query) {

    diag("Running: %s", query);
    PGresult* res = PQexec(conn, query);
    bool success = PQresultStatus(res) == PGRES_COMMAND_OK ||
        PQresultStatus(res) == PGRES_TUPLES_OK;
    if (!success) {
        diag("Failed to execute query '%s': %s",
            query, PQerrorMessage(conn));
        PQclear(res);
        return false;
    }
    PQclear(res);
    return true;
}

void testNoticeAndWarningHandling(PGconn* admin_conn, PGconn* backend_conn) {
    // Set up a notice processor to capture notices
    std::vector<std::string> notices;
    auto noticeProcessor = [](void* arg, const char* message) {
        auto* notices = static_cast<std::vector<std::string>*>(arg);
        notices->emplace_back(message);
    };

    PQsetNoticeProcessor(backend_conn, noticeProcessor, &notices);

    // Execute a query that generates a notice
    const char* noticeQuery = "DO $$ BEGIN RAISE NOTICE 'This is a test notice'; END $$;";
   
    if (!executeQuery(backend_conn, noticeQuery))
        return;

    // Check if the notice was captured
    ok(notices.size() == 1 && notices[0].find("This is a test notice") != std::string::npos, "Notice message was generated");

    // Execute a query that generates a warning
    const char* warningQuery = "DO $$ BEGIN RAISE WARNING 'This is a test warning'; END $$;";
    if (!executeQuery(backend_conn, warningQuery))
		return;

    // Check if the warning was captured
    ok(notices.size() == 2 && notices[1].find("This is a test warning") != std::string::npos, "Warning message was generated");
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*)>> tests = {
    { "Notice and Warning Handling Test", testNoticeAndWarningHandling }
};

void execute_tests(bool with_ssl, bool diff_conn) {

    if (diff_conn == false) {
        PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
        PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

        if (!admin_conn || !backend_conn) {
            BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
            return;
        }

        for (const auto& test : tests) {
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), !diff_conn ? "True" : "False");
            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
    else {
        for (const auto& test : tests) {
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), diff_conn ? "False" : "True");

            PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
            PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

            if (!admin_conn || !backend_conn) {
                BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
                return;
            }
            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
}

int main(int argc, char** argv) {
    if (cl.getEnv())
        return exit_status();

	spawn_internal_noise(cl, internal_noise_mysql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});

	if (cl.use_noise) {
		plan(2 * 2 + 3);
	} else {
		plan(2 * 2);
	}

    execute_tests(true, false);
    execute_tests(false, false);

    return exit_status();
}
