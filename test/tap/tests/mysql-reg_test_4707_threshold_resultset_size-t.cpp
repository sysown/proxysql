 /**
  * @file mysql-reg_test_4707_threshold_resultset_size-t.cpp
  * @brief The test specifically examines the impact of different mysql-threshold_resultset_size threshold values on query response times
  *     and addresses an identified issue caused by variable overflow, which results in slow performance.
  */

#include <string>
#include <sstream>
#include <chrono>
#include "mysql.h"
#include "command_line.h"
#include "noise_utils.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

int main(int argc, char** argv) {
    if (cl.getEnv())
        return exit_status();

	spawn_internal_noise(cl, internal_noise_random_stats_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
	spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

	if (cl.use_noise) {
		plan(6 + 3);
	} else {
		plan(6);
	}

    // Initialize Admin connection
    MYSQL* proxysql_admin = mysql_init(NULL);
    if (!proxysql_admin) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // Connnect to ProxySQL Admin
    if (!mysql_real_connect(proxysql_admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // Initialize Backend connection
    MYSQL* proxysql_backend = mysql_init(NULL);
    if (!proxysql_backend) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_backend));
        return -1;
    }

    // Connnect to ProxySQL Backend
    if (!mysql_real_connect(proxysql_backend, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_backend));
        return -1;
    }
    MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
    MYSQL_QUERY(proxysql_admin, "SET mysql-poll_timeout=2000");
    MYSQL_QUERY(proxysql_admin, "SET mysql-threshold_resultset_size=8000");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
    
    int rc;

    auto start = std::chrono::high_resolution_clock::now();
    rc = mysql_query(proxysql_backend, "SELECT 1");
    auto end = std::chrono::high_resolution_clock::now();

    if (rc == 0) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully. %s", mysql_error(proxysql_backend));
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query. %s", mysql_error(proxysql_admin));
    }

    std::chrono::duration<double, std::milli> duration = end - start;
    ok(duration.count() < 10.00, "Execution time should be less than 10 ms. Actual: %f ms", duration.count());

    MYSQL_QUERY(proxysql_admin, "SET mysql-threshold_resultset_size=536870912");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    start = std::chrono::high_resolution_clock::now();
    rc = mysql_query(proxysql_backend, "SELECT 1");
    end = std::chrono::high_resolution_clock::now();

    if (rc == 0) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully. %s", mysql_error(proxysql_backend));
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query. %s", mysql_error(proxysql_admin));
    }
    duration = end - start;
    ok(duration.count() < 10.00, "Execution time should be less than 10 ms. Actual: %f ms", duration.count());

    MYSQL_QUERY(proxysql_admin, "SET mysql-threshold_resultset_size=1073741824");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    start = std::chrono::high_resolution_clock::now();
    rc = mysql_query(proxysql_backend, "SELECT 1");
    end = std::chrono::high_resolution_clock::now();

    if (rc == 0) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully. %s", mysql_error(proxysql_backend));
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query. %s", mysql_error(proxysql_admin));
    }
    duration = end - start;
    ok(duration.count() < 10.00, "Execution time should be less than 10 ms. Actual: %f ms", duration.count());

    mysql_close(proxysql_backend);
    mysql_close(proxysql_admin);

    return exit_status();
}
