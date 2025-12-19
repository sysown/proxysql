/**
 * @file pgsql-monitor_ssl_connections_test-t.cpp
 * @brief Intention: validate that ProxySQL's PostgreSQL monitor correctly establishes SSL and non-SSL
 *        connections depending on server configuration. The test runs in two phases: first with `use_ssl=1`
 *        to ensure only SSL connection counters increase, and then with `use_ssl=0` to ensure only non-SSL
 *        counters increase. 
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

static long getMonitorValue(PGConnPtr& admin, const char* varname) {
    std::stringstream q;
    q << "SELECT Variable_Value FROM stats_pgsql_global "
        "WHERE Variable_Name='" << varname << "';";

    PGresult* res = PQexec(admin.get(), q.str().c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1;
    }
    long v = atol(PQgetvalue(res, 0, 0));
    PQclear(res);
    return v;
}

static long getConnectInterval(PGConnPtr& admin) {
    PGresult* res = PQexec(admin.get(),
        "SELECT Variable_Value FROM global_variables WHERE Variable_Name='pgsql-monitor_connect_interval';"
    );
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return 1000; // default fallback
    }
    long v = atol(PQgetvalue(res, 0, 0));
    PQclear(res);
    return v;
}

static bool setUseSSL(PGConnPtr& admin, int value) {
    std::stringstream q;
    q << "UPDATE pgsql_servers SET use_ssl=" << value << ";";
    PGresult* res = PQexec(admin.get(), q.str().c_str());
    bool ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);

    PGresult* load = PQexec(admin.get(), "LOAD PGSQL SERVERS TO RUNTIME;");
    bool ok2 = PQresultStatus(load) == PGRES_COMMAND_OK;
    PQclear(load);
    usleep(10000);
    return ok && ok2;
}

static bool setConnectInterval(PGConnPtr& admin, int value) {
    std::stringstream q;
    q << "SET pgsql-monitor_connect_interval=" << value << ";";
    PGresult* res = PQexec(admin.get(), q.str().c_str());
    bool ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    PQclear(res);

    PGresult* load = PQexec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME;");
    bool ok2 = PQresultStatus(load) == PGRES_COMMAND_OK;
    PQclear(load);
    usleep(10000);
    return ok && ok2;
}

int main(int argc, char** argv) {
   
    plan(7);

    if (cl.getEnv())
        return exit_status();

    // -----------------------------------------
    // Connect to ADMIN
    // -----------------------------------------
    auto admin = createNewConnection(ADMIN);
    ok(admin != nullptr, "ADMIN connection created");

    long original_connect_interval_ms = getConnectInterval(admin);
    diag("Original pgsql-monitor_connect_interval = %ld ms", original_connect_interval_ms);

    setConnectInterval(admin, 2000); // set to 2 second for faster test
	usleep(original_connect_interval_ms * 1000); // microseconds

    long connect_interval_ms = getConnectInterval(admin);
    diag("Updated pgsql-monitor_connect_interval = %ld ms", connect_interval_ms);

    // ###############################################################
    //            PHASE 1: TEST SSL (use_ssl = 1)
    // ###############################################################
    diag("---- PHASE 1: Checking SSL monitoring ----");

    ok(setUseSSL(admin, 1), "Set pgsql_server -> use_ssl = 1");

    long initial_ssl = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
    long initial_non = getMonitorValue(admin, "PgSQL_Monitor_non_ssl_connections_OK");

    diag("Initial SSL OK: %ld", initial_ssl);
    diag("Initial NON-SSL OK: %ld", initial_non);

    usleep((connect_interval_ms * 2) * 1000); // microseconds

    long after_ssl = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
    long after_non = getMonitorValue(admin, "PgSQL_Monitor_non_ssl_connections_OK");

    diag("After SSL mode -> SSL OK: %ld", after_ssl);
    diag("After SSL mode -> NON-SSL OK: %ld", after_non);

    ok(after_ssl > initial_ssl,
        "SSL monitoring increased when use_ssl=1");

    ok(after_non == initial_non,
        "NON-SSL monitoring unchanged when use_ssl=1");

    // ###############################################################
    //            PHASE 2: TEST NON-SSL (use_ssl = 0)
    // ###############################################################
    diag("---- PHASE 2: Checking NON-SSL monitoring ----");
   
    ok(setUseSSL(admin, 0), "Set pgsql_server -> use_ssl = 0");
    
    long initial_ssl2 = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
    long initial_non2 = getMonitorValue(admin, "PgSQL_Monitor_non_ssl_connections_OK");

    diag("Initial SSL OK (phase2): %ld", initial_ssl2);
    diag("Initial NON-SSL OK (phase2): %ld", initial_non2);

    usleep((connect_interval_ms * 2) * 1000); // microseconds

    long after_ssl2 = getMonitorValue(admin, "PgSQL_Monitor_ssl_connections_OK");
    long after_non2 = getMonitorValue(admin, "PgSQL_Monitor_non_ssl_connections_OK");

    diag("After NON-SSL mode -> SSL OK: %ld", after_ssl2);
    diag("After NON-SSL mode -> NON-SSL OK: %ld", after_non2);

    ok(after_non2 > initial_non2,
        "NON-SSL monitoring increased when use_ssl=0");

    ok(after_ssl2 == initial_ssl2,
        "SSL monitoring unchanged when use_ssl=0");

    diag("SSL + NON-SSL monitoring test completed successfully");

    setConnectInterval(admin, original_connect_interval_ms); // reset to original value

    return exit_status();
}
