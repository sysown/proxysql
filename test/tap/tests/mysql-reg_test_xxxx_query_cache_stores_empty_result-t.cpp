 /**
  * @file mysql-reg_test_4716_single_semicolon-t.cpp
  * @brief  This test aims to verify that ProxySQL handles a lone semicolon (;) input
  * crashing. The expected behavior is for ProxySQL to either ignore the input or return an
  * appropriate error message, rather than crashing or becoming unresponsive.
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
        if (before.find(metric_name) == before.end() ||
            after.find(metric_name) == after.end()) {
            BAIL_OUT("Metric '%s' not found", metric_name.c_str());
            return false;
        }

        int delta = after[metric_name] - before[metric_name];
        bool result = op(std::max(0, delta), expected);

        std::string bin_op_name = typeid(BinaryOp).name();
        bin_op_name = bin_op_name.substr(3, bin_op_name.size() - 6);

        ok(result, "Metric `%s` should be '%s' %d. Actual %d", metric_name.c_str(), bin_op_name.c_str(), expected, delta);
        return result;
    }
};



int main(int argc, char** argv) {

    plan(10); // Total number of tests planned

    if (cl.getEnv())
        return exit_status();

    // Initialize Admin connection
    MYSQL* proxysql_admin = mysql_init(NULL);
    if (!proxysql_admin) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // Connnect to ProxySQL Admin
    if (!mysql_real_connect(proxysql_admin, cl.host, /*cl.admin_username*/ "admin", /*cl.admin_password*/ "admin", NULL, /*cl.admin_port*/ 6032, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    // Initialize Backend connection
    MYSQL* proxysql_backend = mysql_init(NULL);
    if (!proxysql_backend) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_backend));
        return -1;
    }

	// Connect to Backend
    if (!mysql_real_connect(proxysql_backend, cl.host, /*cl.username*/ "root", /*cl.password*/ "root", NULL, /*cl.port*/ 6033, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_backend));
        return -1;
    }

    MYSQL_QUERY(proxysql_admin, "DELETE FROM mysql_query_rules");
	MYSQL_QUERY(proxysql_admin, "INSERT INTO mysql_query_rules (rule_id,active,match_digest,cache_ttl) VALUES (2,1,'^SELECT',4000)");
	MYSQL_QUERY(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
    MYSQL_QUERY(proxysql_admin, "UPDATE global_variables SET variable_value=0 WHERE variable_name='mysql-query_cache_stores_empty_result'");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    TestMetrics metrics;

    metrics.before = getQueryCacheMetrics(proxysql_admin);

    if (mysql_query(proxysql_backend, "SELECT 1 WHERE 1!=1") == 0) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully. %s", mysql_error(proxysql_backend));
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query. %s", mysql_error(proxysql_admin));
    }

    metrics.after = getQueryCacheMetrics(proxysql_admin);
    
    metrics.checkMetricDelta<>("Query_Cache_Memory_bytes", 0, std::equal_to<int>());
    metrics.checkMetricDelta<>("Query_Cache_count_SET", 0, std::equal_to<int>());
    metrics.checkMetricDelta<>("Query_Cache_bytes_IN", 0, std::equal_to<int>());
    metrics.checkMetricDelta<>("Query_Cache_Entries", 0, std::equal_to<int>());

    metrics.swap();

    MYSQL_QUERY(proxysql_admin, "UPDATE global_variables SET variable_value=1 WHERE variable_name='mysql-query_cache_stores_empty_result'");
    MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");

    if (mysql_query(proxysql_backend, "SELECT 1 WHERE 1!=1") == 0) {
        MYSQL_RES* res = mysql_store_result(proxysql_backend);
        ok(res != nullptr, "Query executed successfully. %s", mysql_error(proxysql_backend));
        mysql_free_result(res);
    }
    else {
        ok(false, "Error executing query. %s", mysql_error(proxysql_admin));
    }

    metrics.after = getQueryCacheMetrics(proxysql_admin);

    metrics.checkMetricDelta<>("Query_Cache_Memory_bytes", 1, std::greater<int>());
    metrics.checkMetricDelta<>("Query_Cache_count_SET", 1, std::equal_to<int>());
    metrics.checkMetricDelta<>("Query_Cache_bytes_IN", 1, std::greater<int>());
    metrics.checkMetricDelta<>("Query_Cache_Entries", 1, std::equal_to<int>());

    mysql_close(proxysql_backend);
    mysql_close(proxysql_admin);

    return exit_status();
}
