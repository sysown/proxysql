/**
 * @file mysql-reg_test_4723_query_cache_stores_empty_result-t.cpp
 * @brief This test verfies that 'mysql-query_cache_stores_empty_result' variable works as expected. 
 *      Specifically, it ensures that when this variable is set to `0`, empty results (zero rows)
 *      are not cached, and when set to `1`, they are cached.
 *      The test verifies this behavior by comparing the metrics before and after query execution.
 */

#include <string>
#include <sstream>

#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

std::map<std::string, int> getQueryCacheMetrics(MYSQL* proxy_admin) {
    const char* query = "SELECT Variable_Name, Variable_Value FROM stats_mysql_global WHERE Variable_Name LIKE 'Query_Cache%';";
    diag("Running: %s", query);

    int query_res = mysql_query(proxy_admin, query);
    if (query_res) {
        BAIL_OUT("Query failed with error: %s", mysql_error(proxy_admin));
        return {};
    }

    std::map<std::string, int> metrics{};
    MYSQL_RES* res = mysql_store_result(proxy_admin);
    if (!res) {
        BAIL_OUT("Failed to store result: %s", mysql_error(proxy_admin));
        return {};
    }

    MYSQL_ROW row;
    while ((row = mysql_fetch_row(res))) {
        metrics[row[0]] = atoi(row[1]);
    }

    mysql_free_result(res);
    return metrics;
}

class TestMetrics {
public:
    std::map<std::string, int> before;
    std::map<std::string, int> after;

    void swap() {
        before.swap(after);
    }

    template<class BinaryOp>
    bool checkMetricDelta(const std::string& metric_name, int expected, BinaryOp op) {
        if (before.find(metric_name) == before.end() || after.find(metric_name) == after.end()) {
            diag("Metric '%s' not found in either before or after map.", metric_name.c_str());
            return false;
        }

        int delta = after[metric_name] - before[metric_name];
        bool result = op(std::max(0, delta), expected);

        diag("Checking metric '%s': Expected delta %d, Actual delta %d", metric_name.c_str(), expected, delta);
        ok(result, "Metric `%s` delta is correct. Expected '%d', got '%d'", metric_name.c_str(), expected, delta);
        return result;
    }
};

// Helper function for executing MySQL queries with error handling
bool exec_query(MYSQL* conn, const char* query) {
    diag("Running query: %s", query);
    int query_res = mysql_query(conn, query);
    if (query_res) {
        diag("Query failed with error: %s", mysql_error(conn));
        return false;
    }
    return true;
}

int main(int argc, char** argv) {
    plan(10); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    // Initialize and connect to ProxySQL Admin
    MYSQL* proxysql_admin = mysql_init(nullptr);
    if (!proxysql_admin) {
        BAIL_OUT("MySQL admin init failed.");
    }

    if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, nullptr, cl.admin_port, nullptr, 0)) {
        BAIL_OUT("Failed to connect to ProxySQL Admin: %s", mysql_error(proxysql_admin));
    }

    // Initialize and connect to ProxySQL Backend
    MYSQL* proxysql_backend = mysql_init(nullptr);
    if (!proxysql_backend) {
        BAIL_OUT("MySQL backend init failed.");
    }

    if (!mysql_real_connect(proxysql_backend, cl.host, cl.username, cl.password, nullptr, cl.port, nullptr, 0)) {
        BAIL_OUT("Failed to connect to ProxySQL Backend: %s", mysql_error(proxysql_backend));
    }

    // Setting up test environment
    MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules");
    MYSQL_QUERY(proxysql_admin, "INSERT INTO mysql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

    // Disable query cache storing empty result
    MYSQL_QUERY(proxysql_admin, "UPDATE global_variables SET variable_value=0 WHERE variable_name='mysql-query_cache_stores_empty_result'");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    TestMetrics metrics;

    metrics.before = getQueryCacheMetrics(proxysql_admin);

    // Execute the test query and check the result
    if (exec_query(proxysql_backend, "SELECT 1 FROM DUAL WHERE 1!=1")) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully.");
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query.");
    }

    // Fetch metrics after query execution
    metrics.after = getQueryCacheMetrics(proxysql_admin);

    metrics.checkMetricDelta("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    metrics.checkMetricDelta("Query_Cache_count_SET", 0, std::equal_to<int>());
    metrics.checkMetricDelta("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    metrics.checkMetricDelta("Query_Cache_Entries", 0, std::equal_to<int>());

    // Swap the before and after metrics for the next phase
    metrics.swap();

    // Enable query cache storing empty result
    MYSQL_QUERY(proxysql_admin, "UPDATE global_variables SET variable_value=1 WHERE variable_name='mysql-query_cache_stores_empty_result'");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    // Execute the same query again and check the result
    if (exec_query(proxysql_backend, "SELECT 1 FROM DUAL WHERE 1!=1")) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully.");
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query.");
    }

    // Fetch metrics again and check for expected changes
    metrics.after = getQueryCacheMetrics(proxysql_admin);

    metrics.checkMetricDelta("Query_Cache_Memory_bytes", 1, std::greater<int>());
    metrics.checkMetricDelta("Query_Cache_count_SET", 1, std::equal_to<int>());
    metrics.checkMetricDelta("Query_Cache_bytes_IN", 1, std::greater<int>());
    metrics.checkMetricDelta("Query_Cache_Entries", 1, std::equal_to<int>());

    // Close the connections
    mysql_close(proxysql_backend);
    mysql_close(proxysql_admin);

    return exit_status();
}
